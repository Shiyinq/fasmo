from typing import Optional


class DomainException(Exception):
    """
    Base class untuk semua domain exceptions.
    Menyederhanakan penulisan exception dengan auto-set message dari ERROR_CODE.
    """
    
    ERROR_CODE: Optional[str] = None
    
    def __init__(self, message: Optional[str] = None):
        """
        Initialize exception dengan message.
        
        Args:
            message: Custom message. Jika None, akan menggunakan ERROR_CODE dari class attribute.
        """
        self.message = message or self.ERROR_CODE or "An error occurred"
        super().__init__(self.message)
