from flask import Flask, request
from flask_restful import Api, Resource

app = Flask(__name__)
api = Api(app)


class Book:
    def __init__(self, id_, title, author):
        self.id = id_
        self.title = title
        self.author = author

    def serialize(self):
        return {"id": self.id, "title": self.title, "Author": self.author}


books = [Book(index, f'Title: {index}', f'Author: {index}') for index in range(1, 11)]


class BooksResources(Resource):
    def get(self):
        return {"books": [book.serialize() for book in books]}

    def post(self):
        data = request.get_json()
        last_id = len(books)
        data["id_"] = last_id + 1
        new_book = Book(**data)
        books.append(new_book)
        return new_book.serialize(), 201


class BookResource(Resource):
    def get_single_book(self, pk):
        book = [b for b in books if b.id == pk]
        if book:
            return book[0]
        return None

    def get(self, pk):
        book = self.get_single_book(pk)
        if not book:
            return {"message": f"Book with id - {pk} doesn't exist"}, 400
        return book.serialize(), 200

    def put(self, pk):
        book = self.get_single_book(pk)
        if not book:
            return {"message": f"Book with id - {pk} doesn't exist"}, 400

        data = request.get_json()
        book.title = data['title']
        book.author = data['author']
        return book.serialize(), 200

    def delete(self, pk):
        book = self.get_single_book(pk)
        if not book:
            return {"message": f"Book with id - {pk} doesn't exist"}, 400
        books.remove(book)
        return {"message": "ok"}, 200


api.add_resource(BooksResources, '/books')
api.add_resource(BookResource, '/books/<int:pk>')

if __name__ == '__main__':
    app.run(debug=True)
