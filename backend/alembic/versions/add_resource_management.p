"""add resource management

Revision ID: resource_management_v1
Revises: 1d4d8e5d1758
Create Date: 2024-01-01 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = 'resource_management_v1'
down_revision = '1d4d8e5d1758'
branch_labels = None
depends_on = None

def upgrade():
    # Add is_active column to resources table
    op.add_column('resources', sa.Column('is_active', sa.Boolean(), server_default='true', nullable=False))
    
    # Add unique constraint on resource name
    op.create_unique_constraint('uq_resource_name', 'resources', ['name'])
    
    # Insert test VMs
    op.execute("""
        INSERT INTO resources (name, type, hostname, port, description, criticality, is_active) 
        VALUES 
        ('RedHat-VM', 'ssh', '192.168.56.101', 22, 'Training RedHat VM for SSH access', 'high', true),
        ('Windows-VM', 'rdp', '192.168.56.102', 3389, 'Training Windows VM for RDP access', 'high', true)
    """)

def downgrade():
    # Remove unique constraint
    op.drop_constraint('uq_resource_name', 'resources', type_='unique')
    
    # Remove is_active column
    op.drop_column('resources', 'is_active')
    
    # Remove test VMs
    op.execute("DELETE FROM resources WHERE name IN ('RedHat-VM', 'Windows-VM')")