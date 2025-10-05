import asyncio
import asyncssh

async def test_ssh_connection():
    private_key = """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBNe0dRATy0l/ryAl4cfhKX+GPhUYPJ6l4HVy70pvApvQAAAJA5nnKhOZ5y
oQAAAAtzc2gtZWQyNTUxOQAAACBNe0dRATy0l/ryAl4cfhKX+GPhUYPJ6l4HVy70pvApvQ
AAAEComN7zSeuK4ZGAM8AibDFbM6ErgwwDFI0+pFLnFCnl+k17R1EBPLSX+vICXhx+Epf4
Y+FRg8nqXgdXLvSm8Cm9AAAADHJvb3RAY29udHJvbAE=
-----END OPENSSH PRIVATE KEY-----"""
    
    conn = None
    try:
        # Clean the key
        private_key = private_key.strip()
        
        # Import key
        key = asyncssh.import_private_key(private_key)
        print("✅ Key imported successfully")
        
        # Test connection
        conn = await asyncssh.connect(
            '192.168.100.48',
            port=22,
            username='webuser',
            client_keys=[key],
            known_hosts=None,
            connect_timeout=10
        )
        print("✅ SSH connection successful")
        
        # Test command execution
        result = await conn.run('echo "SSH test successful"')
        print(f"✅ Command output: {result.stdout.strip()}")
        
    except Exception as e:
        print(f"❌ SSH test failed: {e}")
    finally:
        if conn:
            conn.close()
            await conn.wait_closed()
            print("✅ Connection closed")

if __name__ == "__main__":
    asyncio.run(test_ssh_connection())
