from flask import (
    Flask, render_template, url_for, redirect, request
)
from flask_script import Manager
from flask_sqlalchemy import SQLAlchemy
from flask_admin import Admin, AdminIndexView, helpers, expose
from flask_login import UserMixin, LoginManager, login_user, login_required, current_user
from forms import CardRequestForm
from flask_admin.contrib.sqla import ModelView as BaseModelView
from werkzeug.security import generate_password_hash, check_password_hash
from threading import Thread
from flask_mail import Mail, Message
from paystack import Paystack
import os
import datetime
import json

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)

# TODO: Use environment variables
app.config['SECRET_KEY'] = os.getenv('APP_SECRET_KEY')
app.config['CARD_PRICE'] = 2500
# TODO: Set database uri from environment
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL') or 'sqlite:///' + \
    os.path.join(BASE_DIR, 'sqlite.db')

# Email settings
app.config['MAIL_SERVER'] = os.getenv('EMAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('EMAIL_SERVER_PORT') or 587)
app.config['MAIL_USE_TLS'] = bool(int(os.getenv('EMAIL_USE_TLS') or 1))
app.config['MAIL_USERNAME'] = os.getenv('EMAIL_USERNAME')  # enter your email here
# enter your email here
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('EMAIL_DEFAULT_SENDER')
app.config['MAIL_PASSWORD'] = os.getenv('EMAIL_PASSWORD')  # enter your password here


manager = Manager(app)
db = SQLAlchemy(app)
mail = Mail(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

paystack = Paystack()


class AdminModelView(BaseModelView):

    def is_accessible(self):
        return current_user.is_authenticated and \
            (current_user.user_type == "admin" or
                current_user.user_type == "super_admin")

    def inaccessible_callback(self, name, **kwargs):
        # redirect to login page if user doesn't have access
        return redirect(url_for('login', next=request.url))


class PurchaseAdminModelView(AdminModelView):

    @property
    def can_edit(self):
        return current_user.is_authenticated and (current_user.user_type == "super_admin")


class SuperAdminModelView(AdminModelView):

    def is_accessible(self):
        return current_user.is_authenticated and current_user.user_type == "super_admin"


# Create customized index view class that handles login & registration
class MyAdminIndexView(AdminIndexView):

    @expose('/')
    def index(self):
        if not current_user.is_authenticated and not \
            (current_user.user_type == "admin" or
                current_user.user_type == "super_admin"):
            return redirect(url_for('login'))
        return super(MyAdminIndexView, self).index()


admin = Admin(app, index_view=MyAdminIndexView(),
              name='Waec scratch cards',
              template_mode='bootstrap3')

###############
#
# Models
#
###############


class User(UserMixin, db.Model):
    USER_TYPES = ('regular', 'admin', 'super_admin')
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
    user_type = db.Column(db.Enum(*USER_TYPES), name="user_type", default='regular')

    def __repr__(self):
        return "<User: %s>" % self.email


class WaecECard(db.Model):
    __tablename__ = 'waec_e_cards'

    id = db.Column(db.Integer(), primary_key=True)
    pin = db.Column(db.String(32), nullable=False)
    serial_number = db.Column(db.String(32), nullable=False)
    purchase = db.relationship(
        'Purchase', backref='waec_e_card', uselist=False)

    def __repr__(self):
        return "<WaecECard: %s>" % self.serial_number


class Purchase(db.Model):
    __tablename__ = 'purchases'

    id = db.Column(db.Integer, primary_key=True)
    reference = db.Column(db.String(32), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    card_id = db.Column(db.Integer(), db.ForeignKey('waec_e_cards.id'))
    amount = db.Column(db.Integer)
    date_purchased = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    value_delivered = db.Column(db.Boolean, default=False)
    note = db.Column(db.Text)
    currency = db.Column(db.String(5))

    def __repr__(self):
        return "<Purchase: %s>" % self.reference

    def __str__(self):
        return "%s ─ %s" % (self.reference, self.email)


############
#
# Admin setup
#
#############


@login_manager.user_loader
def load_user(user_id):
    # since the user_id is just the primary key of our user table, use it in the query for the user
    return User.query.get(int(user_id))


def async_send_mail(app, msg, purchase: Purchase):
    with app.app_context():
        mail.send(msg)
        if purchase:
            purchase.value_delivered = True
            db.session.add(purchase)
            db.session.commit()


def send_mail(subject, recipient, template,
              purchase: Purchase = None, **kwargs):
    msg = Message(
        subject, sender=app.config['MAIL_DEFAULT_SENDER'], recipients=[recipient])
    msg.html = render_template(template, **kwargs)
    thr = Thread(target=async_send_mail, args=[app, msg, purchase])
    thr.start()
    return thr


@app.route("/", methods=["GET", "POST"])
def home():
    form = CardRequestForm()
    if form.validate_on_submit():
        email = form.email.data
        name = form.name.data
        note = form.message.data or ""
        metadata = dict(name=name, note=note)

        # Initialize payment
        link = paystack.initialize(
            amount=app.config['CARD_PRICE'] * 100,
            email=email,
            metadata=json.dumps(metadata))

        # Redirect to paystack payment link
        return redirect(link)

    context = dict(form=form)
    return render_template('home.html', **context)


def checkAndGiveValue(data, reference):
    amount = data.get('amount')
    email = (data.get('customer') or dict()).get('email')
    currency = data.get('currency')
    name = (data.get('metadata') or dict()).get('name')
    note = (data.get('metadata') or dict()).get('note')

    # Confirm amount paid
    if amount / 100 >= app.config['CARD_PRICE'] and currency == 'NGN':
        # Deliver value
        purchase = Purchase(
            reference=reference, email=email,
            amount=int(amount), name=name,
            note=note, currency=currency)

        # Check if there's an available card to assign
        card = WaecECard.query.filter_by(purchase=None).first()
        if card:
            purchase.waec_e_card = card

            # Attempt to send email containing card details
            send_thread = send_mail(
                "WAEC scratch card", email, "card_details.html",
                purchase=purchase, pin=card.pin, serial_no=card.serial_number)

        db.session.add(purchase)
        db.session.commit()

        return True

    return False


@app.route("/payment-complete/")
def handle_payment_redirect():
    reference = request.args.get('reference')
    if reference:
        # Proceed to verify payment
        try:
            data = paystack.verify(reference)
        except:
            raise
        if data:
            if checkAndGiveValue(data, reference):
                return render_template('payment_successful.html')

    return "<h1>There was an error in your payment</h1>"


@app.route("/login/")
def login():
    return render_template("login.html")


@app.route('/login/', methods=['POST'])
def login_post():
    email = request.form.get('email')
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False

    user = User.query.filter_by(email=email).first()

    # check if the user actually exists
    # take the user-supplied password, hash it, and compare it to the hashed password in the database
    if not user or not check_password_hash(user.password, password):
        flash('Please check your login details and try again.')
        # if the user doesn't exist or password is wrong, reload the page
        return redirect(url_for('login'))

    # if the above check passes, then we know the user has the right credentials
    login_user(user, remember=remember)
    return redirect(url_for('home'))


@app.route('/signup/')
def signup():
    return render_template("signup.html")


@app.route('/signup/', methods=['POST'])
def signup_post():
    email = request.form.get('email')
    name = request.form.get('name')
    password = request.form.get('password')

    # if this returns a user, then the email already exists in database
    user = User.query.filter_by(email=email).first()

    # if a user is found, we want to redirect back to signup page so user can try again
    if user:
        return redirect(url_for('signup'))

    # create a new user with the form data. Hash the password so the plaintext version isn't saved.
    from werkzeug.security import generate_password_hash, check_password_hash
    new_user = User(email=email, name=name,
                    password=generate_password_hash(password, method='sha256'))

    # add the new user to the database
    db.session.add(new_user)
    db.session.commit()

    login_user(new_user, remember=True)
    return redirect(url_for('home'))


@app.route('/logout/')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


with app.test_request_context():
    paystack.callback_url = url_for('handle_payment_redirect', _external=True)

    admin.add_view(SuperAdminModelView(User, db.session))
    admin.add_view(AdminModelView(WaecECard, db.session))
    admin.add_view(PurchaseAdminModelView(Purchase, db.session))


if __name__ == "__main__":
    manager.run()
