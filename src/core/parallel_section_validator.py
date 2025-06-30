"""
Parallel Section Validation for SentrySearch
Implements concurrent LLM-as-a-Judge validation to improve execution speed and user experience
"""
import anthropic
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Callable
import time
from datetime import datetime
from src.core.section_validator import SectionValidator
from src.core.validation_criteria import SECTION_CRITERIA


class ParallelSectionValidator(SectionValidator):
    """Enhanced validator with parallel processing capabilities"""
    
    def __init__(self, client, max_concurrent_validations=4, max_concurrent_enhancements=2):
        """
        Initialize parallel validator
        
        Args:
            client: Anthropic client
            max_concurrent_validations: Max parallel validation requests (rate limit consideration)
            max_concurrent_enhancements: Max parallel enhancement requests (more expensive)
        """
        super().__init__(client)
        self.max_concurrent_validations = max_concurrent_validations
        self.max_concurrent_enhancements = max_concurrent_enhancements
        self.performance_metrics = {
            'parallel_speedup': 0,
            'validation_time_saved': 0,
            'enhancement_time_saved': 0
        }

    def validate_complete_profile_parallel(self, profile: dict, 
                                         progress_callback: Optional[callable] = None,
                                         tool_name: str = None) -> dict:
        """
        Validate profile using parallel processing for significant speed improvements
        
        Hypothesis: Parallel validation will reduce execution time by 60-80% while maintaining 
        quality and staying within API rate limits
        """
        start_time = time.time()
        
        results = {
            'section_validations': {},
            'overall_score': 0,
            'needs_improvement': False,
            'critical_issues': [],
            'summary': {},
            'recommendations': [],
            'validation_attempts': {},
            'parallel_metrics': {}
        }
        
        # Filter sections for validation
        sections_to_validate = {k: v for k, v in profile.items() 
                               if k not in ['coreMetadata', '_quality_assessment', 'mlGuidance']}
        
        if progress_callback:
            progress_callback(0.8, "🚀 Starting parallel validation...")
        
        # Phase 1: Parallel Initial Validation
        validation_start = time.time()
        section_validations = self._validate_sections_parallel(
            sections_to_validate, profile, progress_callback
        )
        validation_time = time.time() - validation_start
        
        # Store validation results
        for section_name, validation in section_validations.items():
            results['section_validations'][section_name] = validation
            results['validation_attempts'][section_name] = 1
            
            # Track critical issues
            if validation.get('recommendation') == 'RETRY' and validation.get('is_critical'):
                results['critical_issues'].append({
                    'section': section_name,
                    'issues': validation.get('missing_information', [])
                })
        
        # Phase 2: Parallel Enhancement for Low-Scoring Sections
        enhancement_time_saved = 0
        if tool_name:
            enhancement_start = time.time()
            enhanced_results = self._enhance_sections_parallel(
                results, profile, tool_name, progress_callback
            )
            enhancement_time = time.time() - enhancement_start
            
            # Update results with enhanced sections
            results['section_validations'].update(enhanced_results)
            
            # Estimate time saved vs sequential enhancement
            sections_enhanced = len([r for r in enhanced_results.values() 
                                   if r.get('validation_attempts', {}).get('enhanced', False)])
            estimated_sequential_time = sections_enhanced * 45  # Avg 45s per enhancement
            enhancement_time_saved = max(0, estimated_sequential_time - enhancement_time)
        
        # Phase 3: Final consistency check (can remain sequential as it's fast)
        if progress_callback:
            progress_callback(0.95, "🔍 Checking consistency...")
        consistency_check = self._check_consistency(profile)
        results['consistency'] = consistency_check
        
        # Calculate metrics and improvements
        total_time = time.time() - start_time
        estimated_sequential_time = len(sections_to_validate) * 30  # Avg 30s per section
        time_saved = max(0, estimated_sequential_time - total_time)
        speedup_factor = estimated_sequential_time / total_time if total_time > 0 else 1
        
        # Store performance metrics
        results['parallel_metrics'] = {
            'total_execution_time': total_time,
            'estimated_sequential_time': estimated_sequential_time,
            'time_saved_seconds': time_saved,
            'speedup_factor': f"{speedup_factor:.1f}x",
            'validation_time': validation_time,
            'enhancement_time_saved': enhancement_time_saved,
            'sections_processed': len(sections_to_validate),
            'parallel_efficiency': f"{(time_saved/estimated_sequential_time)*100:.1f}%" if estimated_sequential_time > 0 else "0%"
        }
        
        # Calculate final scores
        results['overall_score'] = self._calculate_overall_score(results)
        results['needs_improvement'] = (
            len(results['critical_issues']) > 0 or 
            results['overall_score'] < 3.5
        )
        results['summary'] = self._generate_summary(results)
        results['recommendations'] = self._generate_recommendations(results)
        
        if progress_callback:
            speedup = results['parallel_metrics']['speedup_factor']
            time_saved_min = time_saved / 60
            progress_callback(1.0, f"✅ Parallel validation complete! {speedup} speedup, saved {time_saved_min:.1f} minutes")
        
        return results

    def _validate_sections_parallel(self, sections: dict, profile: dict, 
                                   progress_callback: Optional[callable] = None) -> dict:
        """Execute section validations in parallel with rate limiting"""
        
        def validate_single_section(section_item):
            section_name, section_content = section_item
            try:
                # Add jitter to prevent thundering herd
                time.sleep(random.uniform(0.1, 0.5))
                return section_name, self.validate_section(section_name, section_content, profile)
            except Exception as e:
                print(f"ERROR: Parallel validation failed for {section_name}: {e}")
                return section_name, self._create_error_validation(str(e))
        
        results = {}
        section_items = list(sections.items())
        
        # Use ThreadPoolExecutor for I/O-bound API calls
        with ThreadPoolExecutor(max_workers=self.max_concurrent_validations) as executor:
            # Submit all validation tasks
            future_to_section = {
                executor.submit(validate_single_section, item): item[0] 
                for item in section_items
            }
            
            completed = 0
            for future in as_completed(future_to_section):
                section_name = future_to_section[future]
                try:
                    section_name, validation_result = future.result()
                    results[section_name] = validation_result
                    
                    completed += 1
                    if progress_callback:
                        progress = 0.8 + (0.1 * completed / len(section_items))
                        progress_callback(progress, f"✅ Validated {section_name} ({completed}/{len(section_items)})")
                        
                except Exception as e:
                    print(f"ERROR: Future result failed for {section_name}: {e}")
                    results[section_name] = self._create_error_validation(str(e))
        
        return results

    def _enhance_sections_parallel(self, validation_results: dict, profile: dict, 
                                 tool_name: str, progress_callback: Optional[callable] = None) -> dict:
        """Enhance low-scoring sections in parallel"""
        
        # Identify sections needing improvement
        sections_needing_improvement = []
        for section_name, validation in validation_results['section_validations'].items():
            overall_score = validation.get('scores', {}).get('overall', 0)
            if overall_score < 4.0 and overall_score > 0:
                sections_needing_improvement.append(section_name)
        
        if not sections_needing_improvement:
            return {}
        
        if progress_callback:
            progress_callback(0.9, f"🔧 Enhancing {len(sections_needing_improvement)} sections in parallel...")
        
        def enhance_single_section(section_name):
            try:
                # Add jitter for rate limiting
                time.sleep(random.uniform(0.5, 1.5))
                
                enhanced_content = self._enhance_section_with_web_search(
                    section_name, profile[section_name], tool_name
                )
                
                if enhanced_content and enhanced_content != profile[section_name]:
                    # Update profile and re-validate
                    profile[section_name] = enhanced_content
                    new_validation = self.validate_section(section_name, enhanced_content, profile)
                    new_validation['enhanced'] = True
                    return section_name, new_validation
                
                return section_name, None
                
            except Exception as e:
                print(f"ERROR: Parallel enhancement failed for {section_name}: {e}")
                return section_name, None
        
        enhanced_results = {}
        
        # Use smaller thread pool for enhancement (more expensive operations)
        with ThreadPoolExecutor(max_workers=self.max_concurrent_enhancements) as executor:
            future_to_section = {
                executor.submit(enhance_single_section, section_name): section_name 
                for section_name in sections_needing_improvement
            }
            
            completed = 0
            for future in as_completed(future_to_section):
                section_name = future_to_section[future]
                try:
                    section_name, enhanced_validation = future.result()
                    if enhanced_validation:
                        enhanced_results[section_name] = enhanced_validation
                        validation_results['validation_attempts'][section_name] = 2
                    
                    completed += 1
                    if progress_callback:
                        progress = 0.9 + (0.05 * completed / len(sections_needing_improvement))
                        progress_callback(progress, f"🚀 Enhanced {section_name} ({completed}/{len(sections_needing_improvement)})")
                        
                except Exception as e:
                    print(f"ERROR: Enhancement future failed for {section_name}: {e}")
        
        return enhanced_results


# Add random import that was missing
import random