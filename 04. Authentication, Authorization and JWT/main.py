import enum
from datetime import datetime, timedelta

import jwt
from decouple import config
from flask import Flask, request
from flask_migrate import Migrate
from flask_restful import Api, Resource
from flask_sqlalchemy import SQLAlchemy
from jwt import DecodeError, InvalidSignatureError
from sqlalchemy import func
from marshmallow import Schema, fields, ValidationError, validate, validates
from password_strength import PasswordPolicy
from werkzeug.exceptions import BadRequest, InternalServerError, Forbidden
from werkzeug.security import generate_password_hash
from marshmallow_enum import EnumField
from flask_httpauth import HTTPTokenAuth

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = f"postgresql://{config('DB_USER')}:{config('DB_PASSWORD')}" \
                                        f"@localhost:{config('DB_PORT')}/{config('DB_NAME')}"

db = SQLAlchemy(app)
api = Api(app)
migrate = Migrate(app, db)
auth = HTTPTokenAuth(scheme='Bearer')


@auth.verify_token
def verify_token(token):
    token_decoded_data = User.decode_token(token)
    current_user = User.query.filter_by(id=token_decoded_data["sub"]).first()
    return current_user


def permission_reqiured(permissions_needed):
    def decorated_func(func):
        def wrapper(*args, **kwargs):
            if auth.current_user().role in permissions_needed:
                return func(*args, **kwargs)
            raise Forbidden("You have no permission to access this resource.")
        return wrapper
    return decorated_func


def validate_schema(schema_name):
    def decorated_func(func):
        def wrapper(*args, **kwargs):
            schema = schema_name()
            data = request.get_json()
            errors = schema.validate(data)
            if not errors:
                return func(*args, **kwargs)
            return BadRequest(errors)
        return wrapper
    return decorated_func


class UserRolesEnum(enum.Enum):
    super_admin = "super admin"
    admin = "admin"
    user = "user"


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(255), nullable=False)
    phone = db.Column(db.Text)
    create_on = db.Column(db.DateTime, server_default=func.now())
    updated_on = db.Column(db.DateTime, onupdate=func.now())
    role = db.Column(db.Enum(UserRolesEnum), server_default=UserRolesEnum.user.name, nullable=False)

    def encode_token(self):
        try:
            payload = {
                'exp': datetime.utcnow() + timedelta(days=2),
                'sub': self.id
            }
            return jwt.encode(payload, key=config('SECRET_KEY'), algorithm='HS256')
        except Exception as e:
            raise e

    @staticmethod
    def decode_token(token):
        try:
            return jwt.decode(token, key=config('SECRET_KEY'), algorithms=['HS256'])
        except (DecodeError, InvalidSignatureError) as ex:
            raise BadRequest("Invalid or missing token")
        except Exception:
            raise InternalServerError("Something went wrong")


class ColorEnum(enum.Enum):
    pink = "pink"
    black = "black"
    white = "white"
    yellow = "yellow"


class SizeEnum(enum.Enum):
    xs = "xs"
    s = "s"
    m = "m"
    l = "l"
    xl = "xl"
    xxl = "xxl"


class Clothes(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    color = db.Column(
        db.Enum(ColorEnum),
        default=ColorEnum.white,
        nullable=False
    )
    size = db.Column(
        db.Enum(SizeEnum),
        default=SizeEnum.s,
        nullable=False
    )
    photo = db.Column(db.String(255), nullable=False)
    create_on = db.Column(db.DateTime, server_default=func.now())
    updated_on = db.Column(db.DateTime, onupdate=func.now())


policy = PasswordPolicy.from_names(
    uppercase=1,
    numbers=1,
    special=1,
    nonletters=1
)


def validate_password(value):
    errors = policy.test(value)
    if errors:
        raise ValidationError("Not a valid password")


class BaseUserSchema(Schema):
    email = fields.Email(required=True)
    full_name = fields.String(required=True)

    @validates('full_name')
    def validate_name(self, name):
        if not (3 <= len(name) <= 30):
            raise ValidationError("Name must be between 3 and 30 characters")
        try:
            first_name, last_name = name.split()
        except ValueError:
            raise ValidationError("Name must be two separate words")


users_clothes = db.Table(
    "users_clothes",
    db.Model.metadata,
    db.Column("user_id", db.Integer, db.ForeignKey("user.id")),
    db.Column("clothes_id", db.Integer, db.ForeignKey("clothes.id")),
)


class UserSignInSchema(BaseUserSchema):
    password = fields.String(required=True, validate=validate.And(validate.Length(min=8, max=20), validate_password))


class UserOutSchema(BaseUserSchema):
    id = fields.Integer()


class SingleClothSchemaBase(Schema):
    name = fields.String(required=True)
    color = EnumField(ColorEnum, by_value=True)
    size = EnumField(SizeEnum, by_value=True)


class SingleClothSchemaIn(SingleClothSchemaBase):
    photo = fields.String(required=True)


class SingleClothSchemaOut(SingleClothSchemaBase):
    id = fields.Integer()
    create_on = fields.DateTime()
    updated_on = fields.DateTime()


class UserRegisterResource(Resource):
    @validate_schema(UserSignInSchema)
    def post(self):
        data = request.get_json()
        data['password'] = generate_password_hash(data['password'], method='sha256')
        new_user = User(**data)
        db.session.add(new_user)
        db.session.commit()
        return {"token": new_user.encode_token()}



class UserResource(Resource):
    def get(self, pk):
        user = User.query.filter_by(id=pk).first()
        return UserOutSchema().dump(user)


class ClothesResource(Resource):
    @auth.login_required
    @permission_reqiured([UserRolesEnum.user, UserRolesEnum.super_admin])
    def post(self):
        data = request.get_json()
        schema = SingleClothSchemaIn()
        errors = schema.validate(data)
        if errors:
            return errors
        new_clothes = Clothes(**data)
        db.session.add(new_clothes)
        db.session.commit()
        return SingleClothSchemaOut().dump(new_clothes)

    @auth.login_required
    def get(self):
        current_user = auth.current_user()
        clothes = Clothes.query.all()
        return {"data": clothes}, 200


api.add_resource(UserRegisterResource, '/register')
api.add_resource(ClothesResource, '/clothes')

if __name__ == "__main__":
    app.run(debug=True)
