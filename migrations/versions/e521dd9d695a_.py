"""empty message

Revision ID: e521dd9d695a
Revises: 
Create Date: 2023-06-19 14:53:00.898346

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'e521dd9d695a'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('users',
    sa.Column('email', sa.String(length=255), nullable=False),
    sa.Column('password', sa.String(length=90), nullable=False),
    sa.PrimaryKeyConstraint('email')
    )
    op.create_table('schedule',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('email', sa.String(length=225), nullable=False),
    sa.Column('image', sa.String(length=255), nullable=False),
    sa.Column('scheduleTo', sa.DateTime(), nullable=False),
    sa.Column('date_on', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['email'], ['users.email'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('image_text',
    sa.Column('task_id', sa.Integer(), nullable=False),
    sa.Column('text', sa.Text(), nullable=False),
    sa.ForeignKeyConstraint(['task_id'], ['schedule.id'], ),
    sa.PrimaryKeyConstraint('task_id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('image_text')
    op.drop_table('schedule')
    op.drop_table('users')
    # ### end Alembic commands ###
