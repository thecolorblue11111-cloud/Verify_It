"""
Advanced Search and Tagging System
Provides comprehensive search, filtering, and tagging capabilities for logs
"""

import sqlite3
import re
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
import logging
from security import sanitize_input

# Configure logging
search_logger = logging.getLogger('search')

class SearchFilter:
    """Container for search and filter parameters"""
    def __init__(self):
        self.query: str = ""
        self.method: str = ""
        self.tags: List[str] = []
        self.date_from: Optional[datetime] = None
        self.date_to: Optional[datetime] = None
        self.verification_status: str = ""
        self.recipient: str = ""
        self.has_attachments: Optional[bool] = None
        self.has_blockchain_timestamp: Optional[bool] = None

def create_tags_table():
    """Create tags table if it doesn't exist"""
    try:
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        
        # Create tags table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS tags (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                color TEXT DEFAULT '#6ee7b7',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                usage_count INTEGER DEFAULT 0
            )
        ''')
        
        # Create log_tags junction table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS log_tags (
                log_id INTEGER,
                tag_id INTEGER,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (log_id, tag_id),
                FOREIGN KEY (log_id) REFERENCES logs (id) ON DELETE CASCADE,
                FOREIGN KEY (tag_id) REFERENCES tags (id) ON DELETE CASCADE
            )
        ''')
        
        # Add tags column to logs table if it doesn't exist
        try:
            cursor.execute('ALTER TABLE logs ADD COLUMN tags TEXT')
        except sqlite3.OperationalError:
            # Column already exists
            pass
        
        conn.commit()
        conn.close()
        
        search_logger.info("Tags tables created successfully")
        return True
        
    except Exception as e:
        search_logger.error(f"Failed to create tags tables: {e}")
        return False

def get_or_create_tag(tag_name: str, color: str = '#6ee7b7') -> Optional[int]:
    """
    Get existing tag or create new one
    
    Args:
        tag_name (str): Name of the tag
        color (str): Hex color code for the tag
    
    Returns:
        int: Tag ID or None if failed
    """
    try:
        # Sanitize and validate tag name
        tag_name = sanitize_input(tag_name.strip().lower())
        if not tag_name or len(tag_name) > 50:
            return None
        
        # Validate tag name format
        if not re.match(r'^[a-zA-Z0-9_\-\s]+$', tag_name):
            return None
        
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        
        # Check if tag exists
        cursor.execute('SELECT id FROM tags WHERE name = ?', (tag_name,))
        existing = cursor.fetchone()
        
        if existing:
            tag_id = existing[0]
            # Increment usage count
            cursor.execute('UPDATE tags SET usage_count = usage_count + 1 WHERE id = ?', (tag_id,))
        else:
            # Create new tag
            cursor.execute('''
                INSERT INTO tags (name, color, usage_count) 
                VALUES (?, ?, 1)
            ''', (tag_name, color))
            tag_id = cursor.lastrowid
        
        conn.commit()
        conn.close()
        
        return tag_id
        
    except Exception as e:
        search_logger.error(f"Failed to get/create tag '{tag_name}': {e}")
        return None

def add_tags_to_log(log_id: int, tag_names: List[str]) -> bool:
    """
    Add tags to a log
    
    Args:
        log_id (int): Log ID
        tag_names (List[str]): List of tag names
    
    Returns:
        bool: Success status
    """
    try:
        if not tag_names:
            return True
        
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        
        # Remove existing tags for this log
        cursor.execute('DELETE FROM log_tags WHERE log_id = ?', (log_id,))
        
        tag_ids = []
        for tag_name in tag_names:
            tag_id = get_or_create_tag(tag_name)
            if tag_id:
                tag_ids.append(tag_id)
        
        # Add new tag associations
        for tag_id in tag_ids:
            cursor.execute('''
                INSERT OR IGNORE INTO log_tags (log_id, tag_id) 
                VALUES (?, ?)
            ''', (log_id, tag_id))
        
        # Update tags column in logs table for backward compatibility
        tag_names_str = ', '.join([name.strip() for name in tag_names if name.strip()])
        cursor.execute('UPDATE logs SET tags = ? WHERE id = ?', (tag_names_str, log_id))
        
        conn.commit()
        conn.close()
        
        search_logger.info(f"Added {len(tag_ids)} tags to log {log_id}")
        return True
        
    except Exception as e:
        search_logger.error(f"Failed to add tags to log {log_id}: {e}")
        return False

def get_log_tags(log_id: int) -> List[Dict[str, Any]]:
    """
    Get tags for a specific log
    
    Args:
        log_id (int): Log ID
    
    Returns:
        List[Dict]: List of tag dictionaries
    """
    try:
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT t.id, t.name, t.color, t.usage_count
            FROM tags t
            JOIN log_tags lt ON t.id = lt.tag_id
            WHERE lt.log_id = ?
            ORDER BY t.name
        ''', (log_id,))
        
        tags = []
        for row in cursor.fetchall():
            tags.append({
                'id': row[0],
                'name': row[1],
                'color': row[2],
                'usage_count': row[3]
            })
        
        conn.close()
        return tags
        
    except Exception as e:
        search_logger.error(f"Failed to get tags for log {log_id}: {e}")
        return []

def get_all_tags() -> List[Dict[str, Any]]:
    """
    Get all available tags with usage statistics
    
    Returns:
        List[Dict]: List of all tags
    """
    try:
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, name, color, usage_count, created_at
            FROM tags
            ORDER BY usage_count DESC, name ASC
        ''')
        
        tags = []
        for row in cursor.fetchall():
            tags.append({
                'id': row[0],
                'name': row[1],
                'color': row[2],
                'usage_count': row[3],
                'created_at': row[4]
            })
        
        conn.close()
        return tags
        
    except Exception as e:
        search_logger.error(f"Failed to get all tags: {e}")
        return []

def search_logs(user_id: int, search_filter: SearchFilter, limit: int = 50, offset: int = 0) -> Tuple[List[Dict], int]:
    """
    Advanced search for logs with filtering
    
    Args:
        user_id (int): User ID
        search_filter (SearchFilter): Search parameters
        limit (int): Maximum results to return
        offset (int): Results offset for pagination
    
    Returns:
        Tuple[List[Dict], int]: (results, total_count)
    """
    try:
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        
        # Build base query
        base_query = '''
            SELECT DISTINCT l.id, l.method, l.recipient, l.description, l.timestamp,
                   l.verification_hash, l.ots_status, l.ots_confirmed_at, l.tags,
                   l.email_verification_status, l.file_path
            FROM logs l
        '''
        
        # Build WHERE conditions
        conditions = ['l.user_id = ?']
        params = [user_id]
        
        # Text search in description and recipient
        if search_filter.query:
            query = f"%{sanitize_input(search_filter.query)}%"
            conditions.append('(l.description LIKE ? OR l.recipient LIKE ?)')
            params.extend([query, query])
        
        # Method filter
        if search_filter.method:
            conditions.append('l.method = ?')
            params.append(search_filter.method)
        
        # Recipient filter
        if search_filter.recipient:
            recipient = f"%{sanitize_input(search_filter.recipient)}%"
            conditions.append('l.recipient LIKE ?')
            params.append(recipient)
        
        # Date range filters
        if search_filter.date_from:
            conditions.append('l.timestamp >= ?')
            params.append(search_filter.date_from.strftime('%Y-%m-%d'))
        
        if search_filter.date_to:
            conditions.append('l.timestamp <= ?')
            params.append(search_filter.date_to.strftime('%Y-%m-%d 23:59:59'))
        
        # Verification status filter
        if search_filter.verification_status == 'verified':
            conditions.append('(l.ots_status = "confirmed" OR l.email_verification_status = "verified")')
        elif search_filter.verification_status == 'unverified':
            conditions.append('(l.ots_status IS NULL OR l.ots_status != "confirmed") AND (l.email_verification_status IS NULL OR l.email_verification_status != "verified")')
        elif search_filter.verification_status == 'pending':
            conditions.append('l.ots_status = "pending"')
        
        # Attachments filter
        if search_filter.has_attachments is not None:
            if search_filter.has_attachments:
                conditions.append('l.file_path IS NOT NULL')
            else:
                conditions.append('l.file_path IS NULL')
        
        # Blockchain timestamp filter
        if search_filter.has_blockchain_timestamp is not None:
            if search_filter.has_blockchain_timestamp:
                conditions.append('l.ots_status IS NOT NULL')
            else:
                conditions.append('l.ots_status IS NULL')
        
        # Tags filter
        if search_filter.tags:
            # Join with tags table for tag filtering
            base_query += '''
                LEFT JOIN log_tags lt ON l.id = lt.log_id
                LEFT JOIN tags t ON lt.tag_id = t.id
            '''
            tag_conditions = []
            for tag in search_filter.tags:
                tag_conditions.append('t.name = ?')
                params.append(sanitize_input(tag.strip().lower()))
            
            if tag_conditions:
                conditions.append(f"({' OR '.join(tag_conditions)})")
        
        # Combine conditions
        where_clause = ' AND '.join(conditions)
        
        # Count query
        count_query = f'''
            SELECT COUNT(DISTINCT l.id)
            FROM logs l
            {' LEFT JOIN log_tags lt ON l.id = lt.log_id LEFT JOIN tags t ON lt.tag_id = t.id' if search_filter.tags else ''}
            WHERE {where_clause}
        '''
        
        cursor.execute(count_query, params)
        total_count = cursor.fetchone()[0]
        
        # Main query with ordering and pagination
        main_query = f'''
            {base_query}
            WHERE {where_clause}
            ORDER BY l.timestamp DESC
            LIMIT ? OFFSET ?
        '''
        
        params.extend([limit, offset])
        cursor.execute(main_query, params)
        
        results = []
        for row in cursor.fetchall():
            log_data = {
                'id': row[0],
                'method': row[1],
                'recipient': row[2],
                'description': row[3],
                'timestamp': row[4],
                'verification_hash': row[5],
                'ots_status': row[6],
                'ots_confirmed_at': row[7],
                'tags': row[8],
                'email_verification_status': row[9],
                'file_path': row[10],
                'is_verified': is_log_verified(row[6], row[9]),
                'verification_level': get_verification_level(row[6], row[9])
            }
            
            # Get structured tags
            log_data['tag_list'] = get_log_tags(row[0])
            
            results.append(log_data)
        
        conn.close()
        
        search_logger.info(f"Search returned {len(results)} results out of {total_count} total")
        return results, total_count
        
    except Exception as e:
        search_logger.error(f"Search failed: {e}")
        return [], 0

def is_log_verified(ots_status: str, email_status: str) -> bool:
    """Check if a log is verified"""
    return ots_status == 'confirmed' or email_status == 'verified'

def get_verification_level(ots_status: str, email_status: str) -> str:
    """Get verification level description"""
    if ots_status == 'confirmed' and email_status == 'verified':
        return 'fully_verified'
    elif ots_status == 'confirmed':
        return 'blockchain_verified'
    elif email_status == 'verified':
        return 'email_verified'
    elif ots_status == 'pending':
        return 'pending'
    else:
        return 'unverified'

def get_search_suggestions(user_id: int, query: str) -> Dict[str, List[str]]:
    """
    Get search suggestions based on user's data
    
    Args:
        user_id (int): User ID
        query (str): Partial search query
    
    Returns:
        Dict: Suggestions categorized by type
    """
    try:
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        
        query_pattern = f"%{sanitize_input(query)}%"
        suggestions = {
            'recipients': [],
            'tags': [],
            'methods': []
        }
        
        # Recipient suggestions
        cursor.execute('''
            SELECT DISTINCT recipient FROM logs 
            WHERE user_id = ? AND recipient LIKE ? 
            ORDER BY timestamp DESC LIMIT 5
        ''', (user_id, query_pattern))
        
        suggestions['recipients'] = [row[0] for row in cursor.fetchall()]
        
        # Tag suggestions
        cursor.execute('''
            SELECT DISTINCT t.name FROM tags t
            JOIN log_tags lt ON t.id = lt.tag_id
            JOIN logs l ON lt.log_id = l.id
            WHERE l.user_id = ? AND t.name LIKE ?
            ORDER BY t.usage_count DESC LIMIT 5
        ''', (user_id, query_pattern))
        
        suggestions['tags'] = [row[0] for row in cursor.fetchall()]
        
        # Method suggestions
        if query.lower() in ['email', 'phone', 'sms', 'letter', 'meeting', 'video', 'chat']:
            cursor.execute('''
                SELECT DISTINCT method FROM logs 
                WHERE user_id = ? AND method LIKE ?
                ORDER BY timestamp DESC LIMIT 5
            ''', (user_id, query_pattern))
            
            suggestions['methods'] = [row[0] for row in cursor.fetchall()]
        
        conn.close()
        return suggestions
        
    except Exception as e:
        search_logger.error(f"Failed to get search suggestions: {e}")
        return {'recipients': [], 'tags': [], 'methods': []}
