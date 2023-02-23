from flask import Flask, request
from flask_sqlalchemy import SQLAlchemy
from flask_restful import Api, Resource
from flask_migrate import Migrate

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = f'postgresql://postgres:1123QwER@localhost:5432/store2'

db = SQLAlchemy(app)
api = Api(app)
migrate = Migrate(app, db)


class ModelBook(db.Model):
    __tablename__ = 'books'
    pk = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    author = db.Column(db.String, nullable=False)

    def as_dict(self):
        return {b.name: getattr(self, b.name) for b in self.__table__.columns}


class ResourceBook(Resource):
    def post(self):
        data = request.get_json()
        new_book = ModelBook(**data)
        db.session.add(new_book)
        db.session.commit()
        return new_book.as_dict()


api.add_resource(ResourceBook, '/books/')

if __name__ == '__main__':
    app.run()
