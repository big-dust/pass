"""Increase code length in AuthCode

Revision ID: c8acd6057aa4
Revises: 524ebcd1ffc0
Create Date: 2024-06-15 22:27:09.983865

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = 'c8acd6057aa4'
down_revision = '524ebcd1ffc0'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.alter_column('auth_code', 'code',
               existing_type=mysql.VARCHAR(length=32),
               type_=sa.String(length=128),
               existing_nullable=True)
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.alter_column('auth_code', 'code',
               existing_type=sa.String(length=128),
               type_=mysql.VARCHAR(length=32),
               existing_nullable=True)
    # ### end Alembic commands ###
