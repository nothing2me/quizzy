"""
Quizlet Import Module
Handles importing flashcard sets from Quizlet URLs
"""

import re
import requests
from typing import List, Dict, Optional, Tuple
from urllib.parse import urlparse, parse_qs
import time
import json


class QuizletImporter:
    """Handles importing flashcards from Quizlet URLs"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
    
    def extract_set_id_from_url(self, url: str) -> Optional[str]:
        """Extract Quizlet set ID from URL"""
        try:
            # Handle various Quizlet URL formats
            patterns = [
                r'quizlet\.com/(\d+)/',  # Standard format
                r'quizlet\.com/\w+/(\d+)/',  # With username
                r'set_id=(\d+)',  # Query parameter
            ]
            
            for pattern in patterns:
                match = re.search(pattern, url)
                if match:
                    return match.group(1)
            
            return None
        except Exception:
            return None
    
    def get_quizlet_set_data(self, set_id: str) -> Optional[Dict]:
        """Fetch Quizlet set data using their internal API"""
        try:
            # Quizlet's internal API endpoint
            api_url = f"https://quizlet.com/webapi/3.2/sets/{set_id}"
            
            response = self.session.get(api_url, timeout=10)
            if response.status_code == 200:
                return response.json()
            
            return None
        except Exception as e:
            print(f"Error fetching Quizlet data: {e}")
            return None
    
    def parse_quizlet_data(self, data: Dict) -> Tuple[str, List[Dict]]:
        """Parse Quizlet API response into flashcard format"""
        try:
            set_info = data.get('set', {})
            title = set_info.get('title', 'Imported Quizlet Set')
            
            terms = set_info.get('terms', [])
            flashcards = []
            
            for term in terms:
                front = term.get('word', '').strip()
                back = term.get('definition', '').strip()
                
                if front and back:
                    flashcards.append({
                        'front': front,
                        'back': back
                    })
            
            return title, flashcards
        except Exception as e:
            print(f"Error parsing Quizlet data: {e}")
            return "Imported Quizlet Set", []
    
    def scrape_quizlet_page(self, url: str) -> Tuple[str, List[Dict]]:
        """Fallback method: scrape Quizlet page directly"""
        try:
            response = self.session.get(url, timeout=15)
            if response.status_code != 200:
                return "Import Failed", []
            
            html = response.text
            
            # Extract title
            title_match = re.search(r'<title>([^<]+)</title>', html)
            title = title_match.group(1).replace(' | Quizlet', '') if title_match else 'Imported Quizlet Set'
            
            # Look for various JSON data patterns
            json_patterns = [
                r'window\.Quizlet\.setData\s*=\s*({.*?});',
                r'window\.Quizlet\.setPageData\s*=\s*({.*?});',
                r'window\.Quizlet\.setData\s*=\s*({.*?});',
                r'"setData":\s*({.*?}),',
                r'"setPageData":\s*({.*?}),'
            ]
            
            flashcards = []
            
            for pattern in json_patterns:
                json_match = re.search(pattern, html, re.DOTALL)
                if json_match:
                    try:
                        json_data = json.loads(json_match.group(1))
                        
                        # Try different data structures
                        terms_data = None
                        if 'termIdToTermsMap' in json_data:
                            terms_data = json_data['termIdToTermsMap']
                        elif 'terms' in json_data:
                            terms_data = json_data['terms']
                        elif 'set' in json_data and 'terms' in json_data['set']:
                            terms_data = json_data['set']['terms']
                        
                        if terms_data:
                            for term_id, term_data in terms_data.items():
                                if isinstance(term_data, dict):
                                    front = term_data.get('word', '').strip()
                                    back = term_data.get('definition', '').strip()
                                    
                                    if front and back:
                                        flashcards.append({
                                            'front': front,
                                            'back': back
                                        })
                        
                        if flashcards:
                            break
                            
                    except json.JSONDecodeError:
                        continue
            
            # If no JSON data found, try to extract from HTML structure
            if not flashcards:
                # Look for flashcard content in HTML
                card_pattern = r'<div[^>]*class="[^"]*SetPageTerm[^"]*"[^>]*>.*?<span[^>]*class="[^"]*TermText[^"]*"[^>]*>([^<]+)</span>.*?<span[^>]*class="[^"]*TermText[^"]*"[^>]*>([^<]+)</span>'
                card_matches = re.findall(card_pattern, html, re.DOTALL)
                
                for front, back in card_matches:
                    front = front.strip()
                    back = back.strip()
                    if front and back:
                        flashcards.append({
                            'front': front,
                            'back': back
                        })
            
            return title, flashcards
            
        except Exception as e:
            print(f"Error scraping Quizlet page: {e}")
            return "Import Failed", []
    
    def import_from_url(self, url: str) -> Tuple[str, List[Dict], str]:
        """
        Import flashcards from Quizlet URL
        
        Returns:
            Tuple of (title, flashcards, status_message)
        """
        try:
            # Extract set ID from URL
            set_id = self.extract_set_id_from_url(url)
            
            if not set_id:
                return "Import Failed", [], "Invalid Quizlet URL format"
            
            # Try API method first
            data = self.get_quizlet_set_data(set_id)
            if data:
                title, flashcards = self.parse_quizlet_data(data)
                if flashcards:
                    return title, flashcards, f"Successfully imported {len(flashcards)} flashcards"
            
            # Fallback to scraping
            title, flashcards = self.scrape_quizlet_page(url)
            if flashcards:
                return title, flashcards, f"Successfully imported {len(flashcards)} flashcards"
            
            # If scraping fails, provide instructions for manual import
            return "Manual Import Required", [], self.get_manual_import_instructions(url)
            
        except Exception as e:
            return "Import Failed", [], f"Error importing from Quizlet: {str(e)}"
    
    def get_manual_import_instructions(self, url: str) -> str:
        """Provide instructions for manual Quizlet import"""
        return f"""
        Automatic import failed. Please try this manual method:
        
        1. Go to: {url}
        2. Click the "More" menu (three dots) 
        3. Select "Export"
        4. Choose "Tab-separated values"
        5. Click "Copy text"
        6. Paste the copied text in the "Import Text" option below
        
        This will copy all flashcards in the format: Term<TAB>Definition
        """
    
    def validate_quizlet_url(self, url: str) -> bool:
        """Validate if URL is a valid Quizlet set URL"""
        try:
            parsed = urlparse(url)
            if parsed.netloc not in ['quizlet.com', 'www.quizlet.com']:
                return False
            
            # Check if it looks like a set URL
            return bool(self.extract_set_id_from_url(url))
        except Exception:
            return False


# Convenience function for easy import
def import_quizlet_set(url: str) -> Tuple[str, List[Dict], str]:
    """
    Import flashcards from Quizlet URL
    
    Args:
        url: Quizlet set URL
        
    Returns:
        Tuple of (title, flashcards, status_message)
    """
    importer = QuizletImporter()
    return importer.import_from_url(url)

