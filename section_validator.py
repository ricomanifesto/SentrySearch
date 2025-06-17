"""
Section validation using LLM-as-Judge for quality control
"""
import json
import time
import random
import anthropic
from typing import Optional, List
from datetime import datetime
import re
from validation_criteria import SECTION_CRITERIA, VALIDATION_PROMPTS


class SectionValidator:
    def __init__(self, client):
        """Initialize validator with Anthropic client"""
        self.client = client
        self.validation_history = []
        self.web_search_sources = []  # Track all web search sources across validation
    
    def _extract_json_from_text(self, text: str) -> Optional[dict]:
        """
        Extract JSON from text using multiple strategies for robust parsing
        
        Args:
            text: Text containing JSON
            
        Returns:
            Parsed JSON dict or None if parsing fails
        """
        if not text or not text.strip():
            return None
        
        # Strategy 1: Try to parse the entire text as JSON
        try:
            return json.loads(text.strip())
        except json.JSONDecodeError:
            pass
        
        # Strategy 2: Look for JSON code blocks
        import re
        json_blocks = re.findall(r'```(?:json)?\s*(\{.*?\})\s*```', text, re.DOTALL)
        for block in json_blocks:
            try:
                return json.loads(block.strip())
            except json.JSONDecodeError:
                continue
        
        # Strategy 3: Find the largest valid JSON object using bracket matching
        json_start = text.find('{')
        if json_start == -1:
            return None
        
        # Use bracket matching to find the complete JSON object
        brace_count = 0
        json_end = -1
        in_string = False
        escape_next = False
        
        for i in range(json_start, len(text)):
            char = text[i]
            
            if escape_next:
                escape_next = False
                continue
                
            if char == '\\' and in_string:
                escape_next = True
                continue
                
            if char == '"' and not escape_next:
                in_string = not in_string
                continue
                
            if not in_string:
                if char == '{':
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        json_end = i + 1
                        break
        
        if json_end == -1:
            return None
        
        json_text = text[json_start:json_end]
        
        # Strategy 4: Try to fix common JSON issues
        try:
            return json.loads(json_text)
        except json.JSONDecodeError as e:
            # Try to fix truncated JSON by adding missing closing braces
            try:
                # Count unclosed braces and add them
                open_braces = json_text.count('{') - json_text.count('}')
                if open_braces > 0:
                    fixed_json = json_text + '}' * open_braces
                    return json.loads(fixed_json)
            except json.JSONDecodeError:
                pass
            
            # Try to fix trailing comma issues
            try:
                # Remove trailing commas before closing brackets
                fixed_json = re.sub(r',(\s*[}\]])', r'\1', json_text)
                return json.loads(fixed_json)
            except json.JSONDecodeError:
                pass
            
            # Try to handle incomplete strings at the end
            try:
                # Find the last complete field and truncate there
                last_complete_field = json_text.rfind('",') 
                if last_complete_field > 0:
                    truncated_json = json_text[:last_complete_field + 1]
                    # Count unclosed braces and add them
                    open_braces = truncated_json.count('{') - truncated_json.count('}')
                    if open_braces > 0:
                        truncated_json += '}' * open_braces
                    return json.loads(truncated_json)
            except json.JSONDecodeError:
                pass
            
            # Try to extract just the first level of the JSON object
            try:
                # Parse as much as we can at the root level
                partial_obj = {}
                lines = json_text.split('\n')
                current_field = None
                current_value = []
                
                for line in lines:
                    line = line.strip()
                    if '"' in line and ':' in line and not line.startswith('"'):
                        # This looks like a field definition
                        if current_field and current_value:
                            # Save previous field if we have one
                            try:
                                value_str = '\n'.join(current_value)
                                if value_str.endswith(','):
                                    value_str = value_str[:-1]
                                partial_obj[current_field] = json.loads(value_str)
                            except:
                                pass
                        
                        # Extract field name
                        field_match = re.match(r'\s*"([^"]+)"\s*:\s*(.*)', line)
                        if field_match:
                            current_field = field_match.group(1)
                            current_value = [field_match.group(2)]
                    elif current_field:
                        current_value.append(line)
                
                # Add the last field if we have one
                if current_field and current_value:
                    try:
                        value_str = '\n'.join(current_value)
                        if value_str.endswith(','):
                            value_str = value_str[:-1]
                        partial_obj[current_field] = json.loads(value_str)
                    except:
                        pass
                
                if partial_obj:
                    return partial_obj
            except:
                pass
            
            print(f"DEBUG: JSON parsing error: {e}")
            print(f"DEBUG: JSON text preview: {json_text[:500]}")
            return None
    
    def _api_call_with_retry(self, **kwargs):
        """Make API call with intelligent retry logic using retry-after header"""
        max_retries = 3  # Reduced since we're using smarter delays
        base_delay = 5   # Minimum delay between retries
        
        for attempt in range(max_retries):
            try:
                print(f"DEBUG: Validation API call attempt {attempt + 1}/{max_retries}")
                return self.client.messages.create(**kwargs)
                
            except anthropic.RateLimitError as e:
                if attempt == max_retries - 1:  # Last attempt
                    print(f"DEBUG: Validation rate limit exceeded after {max_retries} attempts")
                    raise e
                
                # Check if the error response has retry-after information
                retry_after = None
                if hasattr(e, 'response') and e.response:
                    retry_after_header = e.response.headers.get('retry-after')
                    if retry_after_header:
                        try:
                            retry_after = float(retry_after_header)
                            print(f"DEBUG: Validation API provided retry-after: {retry_after} seconds")
                        except (ValueError, TypeError):
                            pass
                
                # Use retry-after if available, otherwise exponential backoff
                if retry_after:
                    delay = retry_after + random.uniform(1, 3)  # Add small jitter
                else:
                    # Fallback: exponential backoff with reasonable delays
                    delay = base_delay * (2 ** attempt) + random.uniform(1, 5)
                    # Cap at 2 minutes since token bucket refills continuously
                    delay = min(delay, 120)
                
                print(f"DEBUG: Validation rate limit hit. Waiting {delay:.1f} seconds before retry {attempt + 2}")
                time.sleep(delay)
                
            except Exception as e:
                # For non-rate-limit errors, fail immediately
                print(f"DEBUG: Validation non-rate-limit error: {e}")
                raise e
        
    def validate_section(self, section_name: str, content: dict, 
                        full_context: dict = None) -> dict:
        """
        Validate a specific section using LLM-as-a-Judge approach
        
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
            # Call LLM for validation with retry logic
            response = self._api_call_with_retry(
                model="claude-sonnet-4-20250514",
                max_tokens=2000,
                temperature=0.3,
                messages=[{"role": "user", "content": prompt}]
            )
            
            # Parse response - safe access to content
            if not response.content or len(response.content) == 0:
                raise ValueError("Empty response from validation API")
            
            if not hasattr(response.content[0], 'text'):
                raise ValueError("Response content missing text attribute")
            
            result_text = response.content[0].text.strip()
            validation_result = self._extract_json_from_text(result_text)
            if not validation_result:
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
                                 progress_callback: Optional[callable] = None,
                                 tool_name: str = None) -> dict:
        """
        Validate all sections of a threat intelligence profile with iterative improvement
        
        Args:
            profile: Complete threat intelligence profile
            progress_callback: Optional callback for progress updates
            tool_name: Name of the tool being analyzed (for web search enhancement)
            
        Returns:
            Complete validation results with summary
        """
        results = {
            'section_validations': {},
            'overall_score': 0,
            'needs_improvement': False,
            'critical_issues': [],
            'summary': {},
            'recommendations': [],
            'validation_attempts': {}
        }
        
        # Skip metadata and quality assessment sections
        sections_to_validate = {k: v for k, v in profile.items() 
                               if k not in ['coreMetadata', '_quality_assessment', 'mlGuidance']}
        
        total_sections = len(sections_to_validate)
        completed = 0
        max_validation_attempts = 3
        
        # Initial validation pass
        for section_name, section_content in sections_to_validate.items():
            if progress_callback:
                progress = 0.8 + (0.15 * completed / total_sections)
                progress_callback(progress, f"🔍 Validating {section_name}...")
            
            validation = self.validate_section(section_name, section_content, profile)
            results['section_validations'][section_name] = validation
            results['validation_attempts'][section_name] = 1
            
            # Track critical issues
            if validation.get('recommendation') == 'RETRY' and validation.get('is_critical'):
                results['critical_issues'].append({
                    'section': section_name,
                    'issues': validation.get('missing_information', [])
                })
            
            completed += 1
        
        # Iterative improvement for sections scoring under 4.0
        if tool_name:
            sections_needing_improvement = []
            for section_name, validation in results['section_validations'].items():
                overall_score = validation.get('scores', {}).get('overall', 0)
                if overall_score < 4.0 and overall_score > 0:
                    sections_needing_improvement.append(section_name)
            
            # Perform iterative improvements
            for attempt in range(2, max_validation_attempts + 1):
                if not sections_needing_improvement:
                    break
                
                improved_sections = []
                
                for i, section_name in enumerate(sections_needing_improvement):
                    if progress_callback:
                        progress_callback(0.85, f"🔍 Enhancing {section_name} (attempt {attempt})...")
                    
                    try:
                        # Add small delay between enhancements to avoid rate limiting
                        if i > 0:
                            time.sleep(2)  # 2 second delay between enhancements
                        
                        # Enhance section with web search
                        enhanced_content = self._enhance_section_with_web_search(
                            section_name, profile[section_name], tool_name
                        )
                        
                        if enhanced_content and enhanced_content != profile[section_name]:
                            # Update profile with enhanced content
                            profile[section_name] = enhanced_content
                            
                            # Re-validate enhanced section
                            new_validation = self.validate_section(section_name, enhanced_content, profile)
                            results['section_validations'][section_name] = new_validation
                            results['validation_attempts'][section_name] = attempt
                            
                            new_score = new_validation.get('scores', {}).get('overall', 0)
                            old_score = results['section_validations'][section_name].get('scores', {}).get('overall', 0)
                            
                            print(f"DEBUG: Enhanced {section_name} - Score improved from {old_score} to {new_score}")
                            
                            # Check if section still needs improvement
                            if new_score >= 4.0:
                                improved_sections.append(section_name)
                        else:
                            # No enhancement possible, mark as improved to avoid retry
                            improved_sections.append(section_name)
                            
                    except Exception as e:
                        print(f"DEBUG: Enhancement failed for {section_name}: {e}")
                        improved_sections.append(section_name)  # Don't retry failed enhancements
                
                # Remove improved sections from retry list
                sections_needing_improvement = [s for s in sections_needing_improvement if s not in improved_sections]
        
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
        
        # Add comprehensive sources section if we captured web search sources
        if self.web_search_sources:
            comprehensive_sources = self.generate_comprehensive_sources_section()
            results['comprehensiveWebSearchSources'] = comprehensive_sources
            print(f"DEBUG: Added comprehensive sources section with {len(self.web_search_sources)} total sources")
        
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
            response = self._api_call_with_retry(
                model="claude-sonnet-4-20250514",
                max_tokens=1000,
                temperature=0.3,
                messages=[{"role": "user", "content": prompt}]
            )
            
            # Safe access to response content
            if not response.content or len(response.content) == 0:
                raise ValueError("Empty response from consistency check API")
            
            if not hasattr(response.content[0], 'text'):
                raise ValueError("Response content missing text attribute")
            
            result_text = response.content[0].text.strip()
            consistency_result = self._extract_json_from_text(result_text)
            if consistency_result:
                return consistency_result
            
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
    
    def _enhance_section_with_web_search(self, section_name: str, content: dict, tool_name: str) -> dict:
        """
        Enhance section content using web search for additional information
        
        Args:
            section_name: Name of the section to enhance
            content: Current section content
            tool_name: Name of the tool being analyzed
            
        Returns:
            Enhanced section content or original content if enhancement fails
        """
        try:
            # Generate specific search queries for this section
            search_queries = self._generate_search_queries(section_name, tool_name)
            
            # Create enhancement prompt
            prompt = f"""You are a cybersecurity expert enhancing a threat intelligence section. Use web search to find additional verified information to improve this section.

Section: {section_name}
Tool/Threat: {tool_name}
Current Content: {json.dumps(content, indent=2)}

INSTRUCTIONS:
1. Use web_search_20250305 tool with these specific queries: {search_queries}
2. Find recent, authoritative sources with technical details
3. Look for specific IOCs, technical specifications, detection methods
4. Focus on actionable intelligence that security teams can use
5. Ensure all information is from verified, accessible sources

Enhance the section by:
- Adding missing technical details
- Including specific indicators and artifacts
- Providing more detailed detection/mitigation guidance
- Adding recent threat intelligence findings
- Including authoritative source references

Return the enhanced section content in the same JSON structure, ensuring all new information is properly sourced and technically accurate.

CRITICAL: Only include information from real sources found through web_search_20250305. Do not fabricate URLs or technical details."""

            response = self._api_call_with_retry(
                model="claude-sonnet-4-20250514",
                max_tokens=2000,  # Reduced to prevent truncation
                temperature=0.3,
                messages=[{"role": "user", "content": prompt}],
                tools=[{
                    "type": "web_search_20250305",
                    "name": "web_search"
                }]
            )
            
            # Extract and track web search sources from this enhancement
            sources = self._extract_web_search_sources_from_response(response, section_name, tool_name)
            self.web_search_sources.extend(sources)
            print(f"DEBUG: Captured {len(sources)} web search sources for {section_name}")
            
            # Extract enhanced content from response
            response_text = ""
            if hasattr(response, 'content') and response.content:
                text_blocks = []
                found_tool_result = False
                
                for content_block in response.content:
                    if hasattr(content_block, 'type'):
                        if content_block.type == 'web_search_tool_result':
                            found_tool_result = True
                        elif content_block.type == 'text' and found_tool_result:
                            if hasattr(content_block, 'text'):
                                text_blocks.append(content_block.text)
                
                if text_blocks:
                    response_text = " ".join(text_blocks)
                else:
                    for content_block in response.content:
                        if hasattr(content_block, 'type') and content_block.type == 'text':
                            if hasattr(content_block, 'text'):
                                response_text += content_block.text + "\n"
            
            response_text = response_text.strip()
            
            # Extract JSON from response using proper bracket matching
            enhanced_content = self._extract_json_from_text(response_text)
            if enhanced_content:
                # Validate that enhanced content has more substance
                if self._is_content_enhanced(content, enhanced_content):
                    print(f"DEBUG: Successfully enhanced {section_name} with web search")
                    return enhanced_content
                else:
                    print(f"DEBUG: No significant enhancement for {section_name}")
                    return content
            else:
                print(f"DEBUG: No valid JSON in enhancement response for {section_name}")
                # Log the response for debugging but don't fail completely
                if response_text:
                    print(f"DEBUG: Enhancement response preview: {response_text[:200]}...")
                return content
                
        except Exception as e:
            print(f"DEBUG: Web search enhancement failed for {section_name}: {e}")
            return content
    
    def _generate_search_queries(self, section_name: str, tool_name: str) -> List[str]:
        """Generate targeted search queries for section enhancement"""
        base_queries = [f'"{tool_name}"']
        
        section_specific_queries = {
            "toolOverview": [
                f"{tool_name} malware analysis",
                f"{tool_name} threat intelligence",
                f"{tool_name} security research"
            ],
            "technicalDetails": [
                f"{tool_name} technical analysis",
                f"{tool_name} architecture",
                f"{tool_name} capabilities features"
            ],
            "threatIntelligence": [
                f"{tool_name} threat actor attribution",
                f"{tool_name} campaigns",
                f"{tool_name} APT groups"
            ],
            "forensicArtifacts": [
                f"{tool_name} artifacts IOCs",
                f"{tool_name} forensic analysis",
                f"{tool_name} file signatures"
            ],
            "detectionAndMitigation": [
                f"{tool_name} detection rules",
                f"{tool_name} YARA signatures",
                f"{tool_name} IOCs indicators"
            ],
            "mitigationAndResponse": [
                f"{tool_name} mitigation",
                f"{tool_name} prevention",
                f"{tool_name} incident response"
            ],
            "referencesAndIntelligenceSharing": [
                f"{tool_name} security advisory",
                f"{tool_name} threat report",
                f"{tool_name} intelligence"
            ],
            "integration": [
                f"{tool_name} SIEM integration",
                f"{tool_name} automation",
                f"{tool_name} detection rules"
            ],
            "lineage": [
                f"{tool_name} variants",
                f"{tool_name} evolution",
                f"{tool_name} related tools"
            ],
            "contextualAnalysis": [
                f"{tool_name} usage context",
                f"{tool_name} legitimate use",
                f"{tool_name} dual use"
            ],
            "operationalGuidance": [
                f"{tool_name} operational security",
                f"{tool_name} deployment",
                f"{tool_name} best practices"
            ]
        }
        
        queries = base_queries + section_specific_queries.get(section_name, [])
        return queries[:4]  # Limit to 4 queries to avoid API limits
    
    def _is_content_enhanced(self, original: dict, enhanced: dict) -> bool:
        """Check if enhanced content has meaningful improvements"""
        try:
            # Simple heuristic: enhanced content should have more text
            original_text = json.dumps(original)
            enhanced_text = json.dumps(enhanced)
            
            # Check for meaningful increase in content (at least 20% more)
            if len(enhanced_text) > len(original_text) * 1.2:
                return True
            
            # Check for new fields or substantially longer field values
            original_fields = set(self._get_all_fields(original))
            enhanced_fields = set(self._get_all_fields(enhanced))
            
            return len(enhanced_fields) > len(original_fields)
            
        except Exception:
            return False
    
    def _get_all_fields(self, data, prefix="") -> List[str]:
        """Recursively get all field paths from a nested dict"""
        fields = []
        if isinstance(data, dict):
            for key, value in data.items():
                field_path = f"{prefix}.{key}" if prefix else key
                fields.append(field_path)
                if isinstance(value, (dict, list)):
                    fields.extend(self._get_all_fields(value, field_path))
        elif isinstance(data, list):
            for i, item in enumerate(data):
                if isinstance(item, (dict, list)):
                    fields.extend(self._get_all_fields(item, f"{prefix}[{i}]"))
        return fields
    
    def _extract_web_search_sources_from_response(self, response, section_name: str, tool_name: str) -> List[dict]:
        """
        Extract web search sources from Claude's response based on official API format
        
        Args:
            response: Claude API response object
            section_name: Name of section being enhanced
            tool_name: Name of the threat/tool
            
        Returns:
            List of source dictionaries with metadata
        """
        sources = []
        
        print(f"DEBUG: Extracting sources for {section_name}")
        
        if hasattr(response, 'content') and response.content:
            print(f"DEBUG: Found {len(response.content)} content blocks")
            
            for i, content_block in enumerate(response.content):
                block_type = getattr(content_block, 'type', 'unknown')
                print(f"DEBUG: Content block {i} type: {block_type}")
                
                # Look for web_search_tool_result blocks (official API format)
                if block_type == 'web_search_tool_result':
                    print(f"DEBUG: Found web_search_tool_result block")
                    
                    # Extract content array from the tool result
                    if hasattr(content_block, 'content'):
                        search_content = content_block.content
                        print(f"DEBUG: Tool result content type: {type(search_content)}")
                        
                        if isinstance(search_content, list):
                            print(f"DEBUG: Found {len(search_content)} search results")
                            
                            for j, result in enumerate(search_content):
                                result_type = getattr(result, 'type', 'unknown')
                                print(f"DEBUG: Search result {j} type: {result_type}")
                                
                                # Look for web_search_result items
                                if result_type == 'web_search_result':
                                    url = getattr(result, 'url', '')
                                    title = getattr(result, 'title', '')
                                    page_age = getattr(result, 'page_age', 'unknown')
                                    
                                    print(f"DEBUG: Found search result - URL: {url[:50]}..., Title: {title[:50]}...")
                                    
                                    if url and title:
                                        source = {
                                            'url': url,
                                            'title': title,
                                            'domain': self._extract_domain(url),
                                            'snippet': '',  # No snippet in basic format, will try to extract from content
                                            'publishedDate': self._parse_page_age(page_age),
                                            'accessedDate': datetime.now().strftime('%Y-%m-%d'),
                                            'relevanceToSection': section_name,
                                            'toolContext': tool_name,
                                            'searchPhase': 'enhancement',
                                            'contentType': self._classify_content_type(url, title),
                                            'pageAge': page_age
                                        }
                                        sources.append(source)
                                        print(f"DEBUG: Added source: {title}")
                
                # Also check for server_tool_use blocks that might contain search queries
                elif block_type == 'server_tool_use':
                    tool_name_attr = getattr(content_block, 'name', '')
                    if tool_name_attr == 'web_search':
                        if hasattr(content_block, 'input'):
                            search_input = content_block.input
                            query = getattr(search_input, 'query', '') if hasattr(search_input, 'query') else str(search_input)
                            print(f"DEBUG: Found search query: {query}")
        
        print(f"DEBUG: Total sources extracted for {section_name}: {len(sources)}")
        return sources
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL"""
        import urllib.parse
        try:
            parsed = urllib.parse.urlparse(url)
            return parsed.netloc.lower()
        except:
            return 'unknown'
    
    def _extract_published_date(self, result: dict) -> str:
        """Extract published date from search result"""
        # Try various date fields
        date_fields = ['publishedDate', 'date', 'pubDate', 'published', 'datePublished']
        
        for field in date_fields:
            if field in result and result[field]:
                try:
                    # Try to parse and normalize the date
                    from dateutil import parser
                    parsed_date = parser.parse(str(result[field]))
                    return parsed_date.strftime('%Y-%m-%d')
                except:
                    # If parsing fails, return as string
                    return str(result[field])[:10]  # Truncate to date portion
        
        # Fallback: try to extract date from snippet or title
        text = f"{result.get('title', '')} {result.get('snippet', '')}"
        import re
        date_patterns = [
            r'\b(\d{4}[-/]\d{1,2}[-/]\d{1,2})\b',  # YYYY-MM-DD or YYYY/MM/DD
            r'\b(\d{1,2}[-/]\d{1,2}[-/]\d{4})\b',  # MM-DD-YYYY or MM/DD/YYYY
            r'\b(\w+ \d{1,2}, \d{4})\b',           # Month DD, YYYY
            r'\b(\d{4})\b'                         # Just year
        ]
        
        for pattern in date_patterns:
            match = re.search(pattern, text)
            if match:
                try:
                    from dateutil import parser
                    parsed_date = parser.parse(match.group(1))
                    return parsed_date.strftime('%Y-%m-%d')
                except:
                    return match.group(1)
        
        return 'unknown'
    
    def _parse_page_age(self, page_age: str) -> str:
        """Parse page_age from web search results into a standard date format"""
        if not page_age or page_age == 'unknown':
            return 'unknown'
        
        try:
            # Try to parse the page_age string which might be in various formats
            # Examples: "April 30, 2025", "2025-04-30", etc.
            from dateutil import parser
            parsed_date = parser.parse(page_age)
            return parsed_date.strftime('%Y-%m-%d')
        except:
            # If parsing fails, return the original string or try to extract year
            import re
            year_match = re.search(r'\b(20\d{2})\b', page_age)
            if year_match:
                return year_match.group(1) + '-01-01'  # Default to January 1st
            return page_age
    
    def _classify_content_type(self, url: str, title: str) -> str:
        """Classify the type of content based on URL and title"""
        url_lower = url.lower()
        title_lower = title.lower()
        
        # Check domain patterns
        if any(domain in url_lower for domain in ['cve.mitre.org', 'nvd.nist.gov']):
            return 'CVE/Vulnerability Database'
        elif any(domain in url_lower for domain in ['attack.mitre.org']):
            return 'MITRE ATT&CK Framework'
        elif any(domain in url_lower for domain in ['github.com']):
            return 'Code Repository'
        elif any(domain in url_lower for domain in ['blog', 'medium.com', 'substack']):
            return 'Blog Post'
        elif any(domain in url_lower for domain in ['arxiv.org', 'ieee', 'acm']):
            return 'Academic Paper'
        elif any(domain in url_lower for domain in ['cert', 'cisa.gov', 'us-cert']):
            return 'Government Advisory'
        elif any(domain in url_lower for domain in ['mandiant', 'crowdstrike', 'symantec', 'kaspersky', 'trendmicro']):
            return 'Security Vendor Report'
        
        # Check title patterns
        if any(term in title_lower for term in ['advisory', 'alert', 'bulletin']):
            return 'Security Advisory'
        elif any(term in title_lower for term in ['cve-', 'vulnerability']):
            return 'Vulnerability Report'
        elif any(term in title_lower for term in ['analysis', 'technical', 'deep dive']):
            return 'Technical Analysis'
        elif any(term in title_lower for term in ['threat', 'apt', 'campaign']):
            return 'Threat Intelligence Report'
        elif any(term in title_lower for term in ['detection', 'yara', 'sigma']):
            return 'Detection Rules'
        
        return 'General Article'
    
    def generate_comprehensive_sources_section(self) -> dict:
        """
        Generate comprehensive sources section with all captured web search sources
        organized by temporal order and content type
        
        Returns:
            Dictionary containing organized sources section
        """
        if not self.web_search_sources:
            return {
                'enabled': False,
                'message': 'No web search sources were captured during validation'
            }
        
        # Remove duplicates based on URL
        unique_sources = {}
        for source in self.web_search_sources:
            url = source.get('url', '')
            if url and url not in unique_sources:
                unique_sources[url] = source
            elif url in unique_sources:
                # Merge additional context if same URL found in different sections
                existing = unique_sources[url]
                if source.get('relevanceToSection') not in existing.get('relevanceToSection', ''):
                    existing['relevanceToSection'] += f", {source.get('relevanceToSection', '')}"
        
        sources_list = list(unique_sources.values())
        
        # Sort by published date (most recent first)
        def sort_key(source):
            pub_date = source.get('publishedDate', 'unknown')
            if pub_date == 'unknown':
                return '0000-00-00'  # Put unknown dates at the end
            try:
                # Ensure consistent date format for sorting
                from dateutil import parser
                parsed = parser.parse(pub_date)
                return parsed.strftime('%Y-%m-%d')
            except:
                return pub_date
        
        sources_list.sort(key=sort_key, reverse=True)
        
        # Group by content type
        sources_by_type = {}
        for source in sources_list:
            content_type = source.get('contentType', 'General Article')
            if content_type not in sources_by_type:
                sources_by_type[content_type] = []
            sources_by_type[content_type].append(source)
        
        # Group by publication year for timeline
        sources_by_year = {}
        for source in sources_list:
            pub_date = source.get('publishedDate', 'unknown')
            try:
                if pub_date != 'unknown':
                    year = pub_date[:4] if len(pub_date) >= 4 else 'unknown'
                else:
                    year = 'unknown'
            except:
                year = 'unknown'
            
            if year not in sources_by_year:
                sources_by_year[year] = []
            sources_by_year[year].append(source)
        
        # Format sources for output
        formatted_sources = []
        for source in sources_list:
            formatted_source = {
                'title': source.get('title', 'Unknown Title'),
                'url': source.get('url', ''),
                'domain': source.get('domain', 'unknown'),
                'publishedDate': source.get('publishedDate', 'unknown'),
                'accessedDate': source.get('accessedDate', ''),
                'contentType': source.get('contentType', 'General Article'),
                'relevantSections': source.get('relevanceToSection', ''),
                'snippet': source.get('snippet', '')[:200] + '...' if len(source.get('snippet', '')) > 200 else source.get('snippet', ''),
                'searchContext': source.get('searchPhase', 'enhancement')
            }
            formatted_sources.append(formatted_source)
        
        # Generate statistics
        stats = {
            'totalSources': len(sources_list),
            'uniqueDomains': len(set(s.get('domain', 'unknown') for s in sources_list)),
            'contentTypeBreakdown': {ct: len(sources) for ct, sources in sources_by_type.items()},
            'timelineCoverage': {
                'yearsSpanned': len([y for y in sources_by_year.keys() if y != 'unknown']),
                'sourcesByYear': {year: len(sources) for year, sources in sources_by_year.items()}
            },
            'topDomains': self._get_top_domains(sources_list, 10),
            'sectionCoverage': self._get_section_coverage(sources_list)
        }
        
        return {
            'enabled': True,
            'comprehensiveSourceAnalysis': {
                'overview': {
                    'description': f'Comprehensive analysis of {len(sources_list)} unique sources discovered during web search enhancement across all validation phases',
                    'methodology': 'Sources were automatically captured during Claude AI web search operations, deduplicated by URL, and organized by publication date and content type',
                    'timeRange': self._get_time_range(sources_list),
                    'qualityAssessment': self._assess_source_quality(sources_list)
                },
                'statistics': stats,
                'sourcesByContentType': {ct: [self._format_source_minimal(s) for s in sources] 
                                       for ct, sources in sources_by_type.items()},
                'chronologicalTimeline': {year: [self._format_source_minimal(s) for s in sources] 
                                        for year, sources in sorted(sources_by_year.items(), reverse=True)},
                'allSourcesDetailed': formatted_sources,
                'researchNotes': {
                    'sourceReliability': 'Sources include authoritative cybersecurity vendors, government advisories, academic papers, and technical blogs',
                    'temporalCoverage': f'Sources span multiple years with focus on recent developments',
                    'domainDiversity': f'Information gathered from {stats["uniqueDomains"]} unique domains',
                    'validationPhases': 'Sources collected during automated section enhancement and validation processes'
                }
            },
            'generatedAt': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'captureMethod': 'Automated Web Search During Validation'
        }
    
    def _get_top_domains(self, sources: List[dict], limit: int = 10) -> List[dict]:
        """Get top domains by frequency"""
        domain_counts = {}
        for source in sources:
            domain = source.get('domain', 'unknown')
            domain_counts[domain] = domain_counts.get(domain, 0) + 1
        
        sorted_domains = sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)[:limit]
        return [{'domain': domain, 'count': count} for domain, count in sorted_domains]
    
    def _get_section_coverage(self, sources: List[dict]) -> dict:
        """Get coverage by section"""
        section_counts = {}
        for source in sources:
            sections = source.get('relevanceToSection', '').split(', ')
            for section in sections:
                section = section.strip()
                if section:
                    section_counts[section] = section_counts.get(section, 0) + 1
        
        return section_counts
    
    def _get_time_range(self, sources: List[dict]) -> str:
        """Get time range of sources"""
        dates = []
        for source in sources:
            pub_date = source.get('publishedDate', 'unknown')
            if pub_date != 'unknown':
                try:
                    from dateutil import parser
                    dates.append(parser.parse(pub_date))
                except:
                    pass
        
        if not dates:
            return 'Unknown time range'
        
        dates.sort()
        earliest = dates[0].strftime('%Y-%m-%d')
        latest = dates[-1].strftime('%Y-%m-%d')
        
        if earliest == latest:
            return f'Single date: {earliest}'
        else:
            return f'{earliest} to {latest}'
    
    def _assess_source_quality(self, sources: List[dict]) -> str:
        """Assess overall source quality"""
        high_quality_domains = [
            'cve.mitre.org', 'nvd.nist.gov', 'attack.mitre.org', 'cisa.gov',
            'mandiant.com', 'crowdstrike.com', 'fireeye.com', 'symantec.com',
            'kaspersky.com', 'trendmicro.com', 'cisco.com', 'microsoft.com'
        ]
        
        total_sources = len(sources)
        high_quality_count = sum(1 for s in sources 
                               if any(domain in s.get('domain', '') for domain in high_quality_domains))
        
        quality_ratio = high_quality_count / total_sources if total_sources > 0 else 0
        
        if quality_ratio >= 0.7:
            return 'High quality - Majority from authoritative cybersecurity sources'
        elif quality_ratio >= 0.4:
            return 'Good quality - Mix of authoritative and community sources'
        else:
            return 'Mixed quality - Includes diverse source types'
    
    def _format_source_minimal(self, source: dict) -> dict:
        """Format source for minimal display"""
        return {
            'title': source.get('title', 'Unknown Title'),
            'url': source.get('url', ''),
            'domain': source.get('domain', 'unknown'),
            'publishedDate': source.get('publishedDate', 'unknown'),
            'contentType': source.get('contentType', 'General Article')
        }


class SectionImprover:
    """Improves sections based on validation feedback"""
    
    def __init__(self, client):
        self.client = client
    
    def _extract_json_from_text(self, text: str) -> Optional[dict]:
        """
        Extract JSON from text using multiple strategies for robust parsing
        
        Args:
            text: Text containing JSON
            
        Returns:
            Parsed JSON dict or None if parsing fails
        """
        if not text or not text.strip():
            return None
        
        # Strategy 1: Try to parse the entire text as JSON
        try:
            return json.loads(text.strip())
        except json.JSONDecodeError:
            pass
        
        # Strategy 2: Look for JSON code blocks
        import re
        json_blocks = re.findall(r'```(?:json)?\s*(\{.*?\})\s*```', text, re.DOTALL)
        for block in json_blocks:
            try:
                return json.loads(block.strip())
            except json.JSONDecodeError:
                continue
        
        # Strategy 3: Find the largest valid JSON object using bracket matching
        json_start = text.find('{')
        if json_start == -1:
            return None
        
        # Use bracket matching to find the complete JSON object
        brace_count = 0
        json_end = -1
        in_string = False
        escape_next = False
        
        for i in range(json_start, len(text)):
            char = text[i]
            
            if escape_next:
                escape_next = False
                continue
                
            if char == '\\' and in_string:
                escape_next = True
                continue
                
            if char == '"' and not escape_next:
                in_string = not in_string
                continue
                
            if not in_string:
                if char == '{':
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        json_end = i + 1
                        break
        
        if json_end == -1:
            return None
        
        json_text = text[json_start:json_end]
        
        # Strategy 4: Try to fix common JSON issues
        try:
            return json.loads(json_text)
        except json.JSONDecodeError as e:
            # Try to fix truncated JSON by adding missing closing braces
            try:
                # Count unclosed braces and add them
                open_braces = json_text.count('{') - json_text.count('}')
                if open_braces > 0:
                    fixed_json = json_text + '}' * open_braces
                    return json.loads(fixed_json)
            except json.JSONDecodeError:
                pass
            
            # Try to fix trailing comma issues
            try:
                # Remove trailing commas before closing brackets
                fixed_json = re.sub(r',(\s*[}\]])', r'\1', json_text)
                return json.loads(fixed_json)
            except json.JSONDecodeError:
                pass
            
            # Try to handle incomplete strings at the end
            try:
                # Find the last complete field and truncate there
                last_complete_field = json_text.rfind('",') 
                if last_complete_field > 0:
                    truncated_json = json_text[:last_complete_field + 1]
                    # Count unclosed braces and add them
                    open_braces = truncated_json.count('{') - truncated_json.count('}')
                    if open_braces > 0:
                        truncated_json += '}' * open_braces
                    return json.loads(truncated_json)
            except json.JSONDecodeError:
                pass
            
            # Try to extract just the first level of the JSON object
            try:
                # Parse as much as we can at the root level
                partial_obj = {}
                lines = json_text.split('\n')
                current_field = None
                current_value = []
                
                for line in lines:
                    line = line.strip()
                    if '"' in line and ':' in line and not line.startswith('"'):
                        # This looks like a field definition
                        if current_field and current_value:
                            # Save previous field if we have one
                            try:
                                value_str = '\n'.join(current_value)
                                if value_str.endswith(','):
                                    value_str = value_str[:-1]
                                partial_obj[current_field] = json.loads(value_str)
                            except:
                                pass
                        
                        # Extract field name
                        field_match = re.match(r'\s*"([^"]+)"\s*:\s*(.*)', line)
                        if field_match:
                            current_field = field_match.group(1)
                            current_value = [field_match.group(2)]
                    elif current_field:
                        current_value.append(line)
                
                # Add the last field if we have one
                if current_field and current_value:
                    try:
                        value_str = '\n'.join(current_value)
                        if value_str.endswith(','):
                            value_str = value_str[:-1]
                        partial_obj[current_field] = json.loads(value_str)
                    except:
                        pass
                
                if partial_obj:
                    return partial_obj
            except:
                pass
            
            print(f"DEBUG: JSON parsing error: {e}")
            print(f"DEBUG: JSON text preview: {json_text[:500]}")
            return None
    
    def _api_call_with_retry(self, **kwargs):
        """Make API call with intelligent retry logic using retry-after header"""
        max_retries = 3  # Reduced since we're using smarter delays
        base_delay = 5   # Minimum delay between retries
        
        for attempt in range(max_retries):
            try:
                print(f"DEBUG: Improvement API call attempt {attempt + 1}/{max_retries}")
                return self.client.messages.create(**kwargs)
                
            except anthropic.RateLimitError as e:
                if attempt == max_retries - 1:  # Last attempt
                    print(f"DEBUG: Improvement rate limit exceeded after {max_retries} attempts")
                    raise e
                
                # Check if the error response has retry-after information
                retry_after = None
                if hasattr(e, 'response') and e.response:
                    retry_after_header = e.response.headers.get('retry-after')
                    if retry_after_header:
                        try:
                            retry_after = float(retry_after_header)
                            print(f"DEBUG: Improvement API provided retry-after: {retry_after} seconds")
                        except (ValueError, TypeError):
                            pass
                
                # Use retry-after if available, otherwise exponential backoff
                if retry_after:
                    delay = retry_after + random.uniform(1, 3)  # Add small jitter
                else:
                    # Fallback: exponential backoff with reasonable delays
                    delay = base_delay * (2 ** attempt) + random.uniform(1, 5)
                    # Cap at 2 minutes since token bucket refills continuously
                    delay = min(delay, 120)
                
                print(f"DEBUG: Improvement rate limit hit. Waiting {delay:.1f} seconds before retry {attempt + 2}")
                time.sleep(delay)
                
            except Exception as e:
                # For non-rate-limit errors, fail immediately
                print(f"DEBUG: Improvement non-rate-limit error: {e}")
                raise e
    
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
            response = self._api_call_with_retry(
                model="claude-sonnet-4-20250514",
                max_tokens=4000,
                temperature=0.5,
                messages=[{"role": "user", "content": prompt}]
            )
            
            # Safe access to response content
            if not response.content or len(response.content) == 0:
                raise ValueError("Empty response from section improvement API")
            
            if not hasattr(response.content[0], 'text'):
                raise ValueError("Response content missing text attribute")
            
            result_text = response.content[0].text.strip()
            
            # Extract JSON using proper bracket matching
            improved_content = self._extract_json_from_text(result_text)
            if improved_content:
                return improved_content
            else:
                print(f"No valid JSON found in improvement response")
                return content
                
        except Exception as e:
            print(f"Error improving section {section_name}: {e}")
            return content