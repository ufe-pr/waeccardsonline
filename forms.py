from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, TextAreaField
from wtforms.validators import Email, DataRequired


class CardRequestForm(FlaskForm):
    _required_message = "This field is required"
    name = StringField("Name", validators=[
                       DataRequired(message=_required_message)])
    email = StringField("Email", validators=[
            DataRequired(message=_required_message),
            Email(message="Please provide a valid email address"),
        ],)
    message = TextAreaField("Extra note")
    submit = SubmitField("Submit")