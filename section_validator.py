"""
Section validation using LLM-as-Judge for quality control
"""
import json
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime
import re
from validation_criteria import SECTION_CRITERIA, VALIDATION_PROMPTS


class SectionValidator:
    def __init__(self, client):
        """Initialize validator with Anthropic client"""
        self.client = client
        self.validation_history = []
        
    def validate_section(self, section_name: str, content: dict, 
                        full_context: dict = None) -> dict:
        """
        Validate a specific section using LLM-as-Judge approach
        
        Args:
            section_name: Name of the section to validate
            content: Section content to validate
            full_context: Full profile for context (optional)
            
        Returns:
            Validation results including scores and recommendations
        """
        # Get criteria for this section
        criteria = SECTION_CRITERIA.get(section_name, {})
        if not criteria:
            return self._create_default_validation()
        
        # Format the validation prompt
        prompt = VALIDATION_PROMPTS["section_validation"].format(
            section_name=section_name,
            content=json.dumps(content, indent=2),
            required_fields=", ".join(criteria.get("required_fields", [])),
            quality_checks="\n   - ".join(criteria.get("quality_checks", [])),
            min_score=criteria.get("min_score", 3.5)
        )
        
        try:
            # Call LLM for validation
            response = self.client.messages.create(
                model="claude-3-5-sonnet-20241022",
                max_tokens=2000,
                temperature=0.3,
                messages=[{"role": "user", "content": prompt}]
            )
            
            # Parse response
            result_text = response.content[0].text.strip()
            json_match = re.search(r'\{.*\}', result_text, re.DOTALL)
            if json_match:
                validation_result = json.loads(json_match.group())
            else:
                raise ValueError("No valid JSON in response")
                
            # Add metadata
            validation_result['section_name'] = section_name
            validation_result['timestamp'] = datetime.now().isoformat()
            validation_result['is_critical'] = criteria.get('critical', False)
            
            # Store in history
            self.validation_history.append(validation_result)
            
            return validation_result
            
        except Exception as e:
            print(f"Validation error for {section_name}: {e}")
            return self._create_error_validation(str(e))
    
    def validate_complete_profile(self, profile: dict, 
                                 progress_callback: Optional[callable] = None) -> dict:
        """
        Validate all sections of a threat intelligence profile
        
        Args:
            profile: Complete threat intelligence profile
            progress_callback: Optional callback for progress updates
            
        Returns:
            Complete validation results with summary
        """
        results = {
            'section_validations': {},
            'overall_score': 0,
            'needs_improvement': False,
            'critical_issues': [],
            'summary': {},
            'recommendations': []
        }
        
        # Skip metadata and quality assessment sections
        sections_to_validate = {k: v for k, v in profile.items() 
                               if k not in ['coreMetadata', '_quality_assessment']}
        
        total_sections = len(sections_to_validate)
        completed = 0
        
        # Validate each section
        for section_name, section_content in sections_to_validate.items():
            if progress_callback:
                progress = 0.8 + (0.15 * completed / total_sections)
                progress_callback(progress, f"🔍 Validating {section_name}...")
            
            validation = self.validate_section(section_name, section_content, profile)
            results['section_validations'][section_name] = validation
            
            # Track critical issues
            if validation.get('recommendation') == 'RETRY' and validation.get('is_critical'):
                results['critical_issues'].append({
                    'section': section_name,
                    'issues': validation.get('missing_information', [])
                })
            
            completed += 1
        
        # Check cross-section consistency
        if progress_callback:
            progress_callback(0.95, "🔍 Checking consistency...")
        
        consistency_check = self._check_consistency(profile)
        results['consistency'] = consistency_check
        
        # Calculate overall score
        results['overall_score'] = self._calculate_overall_score(results)
        
        # Determine if improvement is needed
        results['needs_improvement'] = (
            len(results['critical_issues']) > 0 or 
            results['overall_score'] < 3.5
        )
        
        # Generate summary and recommendations
        results['summary'] = self._generate_summary(results)
        results['recommendations'] = self._generate_recommendations(results)
        
        return results
    
    def _check_consistency(self, profile: dict) -> dict:
        """Check consistency across sections"""
        sections_summary = {
            name: {
                'has_content': bool(content),
                'field_count': len(content) if isinstance(content, dict) else 0
            }
            for name, content in profile.items()
            if name not in ['coreMetadata', '_quality_assessment']
        }
        
        prompt = VALIDATION_PROMPTS["consistency_check"].format(
            sections=json.dumps(sections_summary, indent=2)
        )
        
        try:
            response = self.client.messages.create(
                model="claude-3-5-sonnet-20241022",
                max_tokens=1000,
                temperature=0.3,
                messages=[{"role": "user", "content": prompt}]
            )
            
            result_text = response.content[0].text.strip()
            json_match = re.search(r'\{.*\}', result_text, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
            
        except Exception as e:
            print(f"Consistency check error: {e}")
        
        return {
            "consistency_score": 3.0,
            "inconsistencies": [],
            "recommendations": []
        }
    
    def _calculate_overall_score(self, results: dict) -> float:
        """Calculate weighted overall score"""
        total_score = 0
        total_weight = 0
        
        for section_name, validation in results['section_validations'].items():
            scores = validation.get('scores', {})
            overall = scores.get('overall', 0)
            
            # Weight critical sections more heavily
            weight = 1.5 if validation.get('is_critical') else 1.0
            
            total_score += overall * weight
            total_weight += weight
        
        # Include consistency score
        consistency_score = results.get('consistency', {}).get('consistency_score', 3.0)
        total_score += consistency_score * 0.5
        total_weight += 0.5
        
        return round(total_score / total_weight, 2) if total_weight > 0 else 0
    
    def _generate_summary(self, results: dict) -> dict:
        """Generate summary of validation results"""
        section_scores = {}
        for section, validation in results['section_validations'].items():
            section_scores[section] = validation.get('scores', {}).get('overall', 0)
        
        return {
            'total_sections': len(results['section_validations']),
            'passed_sections': sum(1 for v in results['section_validations'].values() 
                                 if v.get('recommendation') == 'PASS'),
            'failed_sections': sum(1 for v in results['section_validations'].values() 
                                 if v.get('recommendation') == 'RETRY'),
            'average_score': results['overall_score'],
            'weakest_sections': sorted(section_scores.items(), key=lambda x: x[1])[:3],
            'strongest_sections': sorted(section_scores.items(), key=lambda x: x[1], reverse=True)[:3]
        }
    
    def _generate_recommendations(self, results: dict) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        # Critical issues first
        if results['critical_issues']:
            for issue in results['critical_issues']:
                recommendations.append(
                    f"CRITICAL: Fix {issue['section']} - " + 
                    ", ".join(issue['issues'][:2])
                )
        
        # Low scoring sections
        for section, validation in results['section_validations'].items():
            if validation.get('scores', {}).get('overall', 0) < 3.0:
                improvements = validation.get('specific_improvements', [])
                if improvements:
                    recommendations.append(
                        f"Improve {section}: {improvements[0]}"
                    )
        
        # Consistency issues
        inconsistencies = results.get('consistency', {}).get('inconsistencies', [])
        if inconsistencies:
            recommendations.append(
                f"Fix inconsistencies: {inconsistencies[0]}"
            )
        
        return recommendations[:5]  # Top 5 recommendations
    
    def _create_default_validation(self) -> dict:
        """Create default validation for unknown sections"""
        return {
            'scores': {
                'completeness': 3.0,
                'technical_accuracy': 3.0,
                'source_quality': 3.0,
                'actionability': 3.0,
                'relevance': 3.0,
                'overall': 3.0
            },
            'missing_information': [],
            'weak_areas': ["Section type not recognized for validation"],
            'technical_issues': [],
            'specific_improvements': [],
            'recommendation': 'ENHANCE',
            'reasoning': 'Default validation applied'
        }
    
    def _create_error_validation(self, error: str) -> dict:
        """Create error validation result"""
        return {
            'scores': {
                'completeness': 0,
                'technical_accuracy': 0,
                'source_quality': 0,
                'actionability': 0,
                'relevance': 0,
                'overall': 0
            },
            'missing_information': ["Validation failed"],
            'weak_areas': [f"Error: {error}"],
            'technical_issues': ["Validation error occurred"],
            'specific_improvements': ["Retry validation"],
            'recommendation': 'RETRY',
            'reasoning': f'Validation error: {error}'
        }


class SectionImprover:
    """Improves sections based on validation feedback"""
    
    def __init__(self, client):
        self.client = client
    
    def improve_section(self, section_name: str, content: dict, 
                       validation_result: dict) -> dict:
        """
        Improve a section based on validation feedback
        
        Args:
            section_name: Name of section to improve
            content: Current section content
            validation_result: Validation results with issues
            
        Returns:
            Improved section content
        """
        prompt = VALIDATION_PROMPTS["improvement_prompt"].format(
            section_name=section_name,
            content=json.dumps(content, indent=2),
            issues=json.dumps({
                'missing': validation_result.get('missing_information', []),
                'weak_areas': validation_result.get('weak_areas', []),
                'technical_issues': validation_result.get('technical_issues', [])
            }, indent=2),
            improvements=json.dumps(
                validation_result.get('specific_improvements', []), 
                indent=2
            )
        )
        
        try:
            response = self.client.messages.create(
                model="claude-3-5-sonnet-20241022",
                max_tokens=4000,
                temperature=0.5,
                messages=[{"role": "user", "content": prompt}]
            )
            
            result_text = response.content[0].text.strip()
            
            # Extract JSON
            json_match = re.search(r'\{.*\}', result_text, re.DOTALL)
            if json_match:
                improved_content = json.loads(json_match.group())
                return improved_content
            else:
                print(f"No valid JSON found in improvement response")
                return content
                
        except Exception as e:
            print(f"Error improving section {section_name}: {e}")
            return content