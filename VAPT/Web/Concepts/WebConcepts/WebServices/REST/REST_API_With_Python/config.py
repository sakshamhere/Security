import pathlib
import connexion
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow


basedir = pathlib.Path(__file__).parent.resolve()

connex_app = connexion.App(__name__, specification_dir=basedir)


app = connex_app.app

app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{basedir / 'people.db'}"

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False


db = SQLAlchemy(app)

ma = Marshmallow(app)


# Here’s what the above code is doing:

#     Lines 3 to 6 import the built-in pathlib as well as the third-party libraries connexion, SQLAlchemy, and Marshmallow.

#     Line 8 creates the variable basedir pointing to the directory that the program is running in.

#     Line 9 uses the basedir variable to create the Connexion app instance and give it the path to the directory that contains your specification file.

#     Line 11 creates a variable, app, which is the Flask instance initialized by Connexion.

#     Line 12 tell SQLAlchemy to use SQLite as the database and a file named people.db in the current directory as the database file.

#     Line 13 turns the SQLAlchemy event system off. The event system generates events that are useful in event-driven programs, but it adds significant overhead. Since you’re not creating an event-driven program, you turn this feature off.

#     Line 15 initializes SQLAlchemy by passing the ap configuration information to SQLAlchemy and assigning the result to a db variable.

#     Line 16 initializes Marshmallow and allows it to work with the SQLAlchemy components attached to the app.
