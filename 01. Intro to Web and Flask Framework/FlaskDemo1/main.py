from flask import Flask, request
from flask_restful import Api, Resource

app = Flask(__name__)
api = Api(app)


class Book:
    def __init__(self, title, author):
        self.title = title
        self.author = author

    def serialize(self):
        return {"title": self.title, "author": self.author}


books = [Book(title=index, author=index) for index in range(10)]


class MyBooks(Resource):
    def get(self):
        return {"books": [book.serialize() for book in books]}

    def post(self):
        data = request.get_json()
        new_book = Book(**data)
        books.append(new_book)
        return new_book.serialize(), 201

api.add_resource(MyBooks, '/')

if __name__ == '__main__':
    app.run(debug=True)
