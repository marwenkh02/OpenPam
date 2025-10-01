import asyncio
import socket
# import asyncssh
import aiohttp
import time
from typing import Optional, Dict, Any
from sqlalchemy.orm import Session
from .models import Resource, ResourceCheck

class HealthCheckService:
    def __init__(self):
        self.timeout = 10  # seconds
    
    async def check_resource_health(self, resource: Resource) -> Dict[str, Any]:
        """Check if a resource is online and accessible"""
        start_time = time.time()
        
        try:
            if resource.type in ['ssh', 'db']:
                result = await self._check_port(resource.hostname, resource.port or self._get_default_port(resource.type))
            elif resource.type == 'web':
                result = await self._check_http(resource.hostname, resource.port)
            elif resource.type == 'api':
                result = await self._check_api(resource.hostname, resource.port)
            elif resource.type == 'rdp':
                result = await self._check_port(resource.hostname, resource.port or 3389)
            else:
                result = await self._check_port(resource.hostname, resource.port or 22)
            
            response_time = int((time.time() - start_time) * 1000)  # Convert to ms
            
            return {
                "is_online": True,
                "response_time": response_time,
                "error_message": None
            }
            
        except Exception as e:
            return {
                "is_online": False,
                "response_time": None,
                "error_message": str(e)
            }
    
    async def _check_port(self, hostname: str, port: int) -> bool:
        """Check if a port is open"""
        try:
            # Use asyncio to avoid blocking
            loop = asyncio.get_event_loop()
            await asyncio.wait_for(
                loop.run_in_executor(None, self._sync_check_port, hostname, port),
                timeout=self.timeout
            )
            return True
        except Exception as e:
            raise Exception(f"Port {port} not accessible: {str(e)}")
    
    def _sync_check_port(self, hostname: str, port: int) -> bool:
        """Synchronous port check"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((hostname, port))
                return result == 0
        except Exception as e:
            raise Exception(f"Socket error: {str(e)}")
    
    async def _check_http(self, hostname: str, port: Optional[int]) -> bool:
        """Check HTTP/HTTPS endpoint"""
        try:
            url = f"http://{hostname}"
            if port:
                url += f":{port}"
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=self.timeout)) as response:
                    return response.status < 500
        except Exception as e:
            raise Exception(f"HTTP check failed: {str(e)}")
    
    async def _check_api(self, hostname: str, port: Optional[int]) -> bool:
        """Check API endpoint"""
        try:
            url = f"http://{hostname}"
            if port:
                url += f":{port}"
            url += "/health"  # Common health endpoint
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=self.timeout)) as response:
                    return response.status < 500
        except Exception:
            # If /health fails, try basic connectivity
            return await self._check_port(hostname, port or 80)
    
    def _get_default_port(self, resource_type: str) -> int:
        """Get default port for resource type"""
        defaults = {
            'ssh': 22,
            'db': 5432,  # PostgreSQL default
            'web': 80,
            'api': 80,
            'rdp': 3389,
            'service': 8080
        }
        return defaults.get(resource_type, 22)

# Global instance
health_check_service = HealthCheckService()