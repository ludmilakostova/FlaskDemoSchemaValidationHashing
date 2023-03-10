"""add many to many relationship user to clothes

Revision ID: 67ecc6219a05
Revises: 371402c16574
Create Date: 2023-02-24 18:09:38.987362

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '67ecc6219a05'
down_revision = '371402c16574'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('users_clothes',
    sa.Column('user_id', sa.Integer(), nullable=True),
    sa.Column('clothes_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['clothes_id'], ['clothes.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], )
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('users_clothes')
    # ### end Alembic commands ###
