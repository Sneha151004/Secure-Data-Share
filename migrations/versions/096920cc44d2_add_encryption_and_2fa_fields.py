"""Add encryption and 2FA fields

Revision ID: 096920cc44d2
Revises: 
Create Date: 2024-12-13 13:39:04.746005

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '096920cc44d2'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('data_record', schema=None) as batch_op:
        batch_op.add_column(sa.Column('is_encrypted', sa.Boolean(), nullable=True))
        batch_op.add_column(sa.Column('encryption_status', sa.String(length=20), nullable=True))

    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('two_factor_enabled', sa.Boolean(), nullable=True))
        batch_op.add_column(sa.Column('phone_number', sa.String(length=20), nullable=True))
        batch_op.add_column(sa.Column('two_factor_secret', sa.String(length=32), nullable=True))
        batch_op.add_column(sa.Column('default_encryption_enabled', sa.Boolean(), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_column('default_encryption_enabled')
        batch_op.drop_column('two_factor_secret')
        batch_op.drop_column('phone_number')
        batch_op.drop_column('two_factor_enabled')

    with op.batch_alter_table('data_record', schema=None) as batch_op:
        batch_op.drop_column('encryption_status')
        batch_op.drop_column('is_encrypted')

    # ### end Alembic commands ###
