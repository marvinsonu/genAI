from flask import Flask, render_template
from controller.config import Config
from controller.database import db
from controller.model import User, Role, UserRole

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)
with app.app_context():
    db.create_all()

    


@app.route('/') #Decorator 
def home():
    return render_template('index.html')


if __name__ == '__main__':
    app.run(debug=True)



