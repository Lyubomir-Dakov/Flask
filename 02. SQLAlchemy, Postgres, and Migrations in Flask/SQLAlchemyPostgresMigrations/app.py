from decouple import config
from flask import Flask, request
from flask_sqlalchemy import SQLAlchemy
from flask_restful import Api, Resource
from flask_migrate import Migrate

app = Flask(__name__)
app.config[
    'SQLALCHEMY_DATABASE_URI'] = f"postgresql://{config('DB_USER')}:{config('DB_PASSWORD')}" \
                                 f"@localhost:{config('DB_PORT')}/{config('DB_NAME')}"

db = SQLAlchemy(app)
api = Api(app)
migrate = Migrate(app, db)


class ModelBook(db.Model):
    __tablename__ = 'books'
    pk = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    author = db.Column(db.String, nullable=False)
    test_column = db.Column(db.String)
    reader_pk = db.Column(db.Integer, db.ForeignKey('readers.pk'))
    reader = db.Relationship('ModelReader')

    def as_dict(self):
        return {b.name: getattr(self, b.name) for b in self.__table__.columns}


class ModelReader(db.Model):
    __tablename__ = 'readers'
    pk = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String, nullable=False)
    last_name = db.Column(db.String, nullable=False)
    books = db.relationship("ModelBook", backref="book", lazy='dynamic')


class ResourceBook(Resource):
    def post(self):
        data = request.get_json()
        reader_pk = data.pop('reader_pk')
        new_book = ModelBook(**data)
        new_book.reader_pk = reader_pk
        db.session.add(new_book)
        db.session.commit()
        return new_book.as_dict()


api.add_resource(ResourceBook, '/books/')

if __name__ == '__main__':
    app.run()
