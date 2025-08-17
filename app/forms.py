from flask_wtf import FlaskForm
from wtforms import StringField, FileField, TextAreaField
from wtforms.validators import DataRequired, Length
from flask_wtf.file import FileAllowed

class LogForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(max=200)])
    description = TextAreaField('Description', validators=[DataRequired(), Length(max=1000)])
    attachment = FileField(
        'Attachment',
        validators=[FileAllowed(['pdf', 'jpg', 'jpeg', 'png'], 'Only PDF and image files allowed!')]
    )
    tags = StringField('Tags (comma separated)', validators=[Length(max=200)])