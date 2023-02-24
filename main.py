import enum

from decouple import config
from flask import Flask, request
from flask_migrate import Migrate
from flask_restful import Api, Resource
from flask_sqlalchemy import SQLAlchemy
from marshmallow import Schema, fields, validate, ValidationError
from marshmallow_enum import EnumField
from password_strength import PasswordPolicy
from sqlalchemy import func
from werkzeug.security import generate_password_hash


app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = f'postgresql://{config("DB_USER")}:{config("DB_PASSWORD")}@localhost:{config("DB_PORT")}/{config("DB_NAME")}'

db = SQLAlchemy(app)
api = Api(app)
migrate = Migrate(app, db)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(255), nullable=False)
    phone = db.Column(db.Text)
    create_on = db.Column(db.DateTime, server_default=func.now())
    updated_on = db.Column(db.DateTime, onupdate=func.now())


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


users_clothes = db.Table(
    "users_clothes",
    db.Model.metadata,
    db.Column("user_id", db.Integer, db.ForeignKey("user.id")),
    db.Column("clothes_id", db.Integer, db.ForeignKey("clothes.id")),
)



def validate_name(value):
    try:
        first_name, last_name = value.split()
    except ValueError:
        raise ValidationError("At least 2 names are required")


policy = PasswordPolicy.from_names(
    uppercase=1,  # need min. 1 uppercase letters
    numbers=1,  # need min. 1 digits
    special=1,  # need min. 1 special characters
    nonletters=1,  # need min. 1 non-letter characters (digits, specials, anything)
)


def validate_password(value):
    errors = policy.test(value)
    if errors:
        raise ValidationError(f"Not a valid password")


class BaseUserSchema(Schema):
    email = fields.Email(required=True)
    full_name = fields.String(required=True, validate=validate.And(validate.Length(min=3, max=22), validate_name))


class UserSignInSchema(BaseUserSchema):
    password = fields.String(required=True,
        validate=validate.And(validate.Length(min=8, max=20), validate_password))


class UserOutSchema(BaseUserSchema):
    id = fields.Integer()


class SingleClothSchema(Schema):
    name = fields.String(required=True)
    color = EnumField(ColorEnum, by_value=True)
    size = EnumField(SizeEnum, by_value=True)


class SingleClothInSchema(SingleClothSchema):
    photo = fields.String()


class SingleClothOutSchema(SingleClothSchema):
    id = fields.Integer()
    create_on = fields.DateTime()
    updated_on = fields.DateTime()



class UserRegisterResource(Resource):
    def post(self):
        data = request.get_json()
        schema = UserSignInSchema()
        errors = schema.validate(data)
        if not errors:
            data["password"] = generate_password_hash(data['password'], method='sha256')
            user = User(**data)
            db.session.add(user)
            db.session.commit()
            return UserOutSchema().dump(user)
        return errors


class ClothesResource(Resource):
    def post(self):
        data = request.get_json()
        schema = SingleClothInSchema()
        errors = schema.validate(data)
        if errors:
            return 400
        clothes = Clothes(**data)
        db.session.add(clothes)
        db.session.commit()
        return SingleClothOutSchema().dump(clothes)


api.add_resource(UserRegisterResource, "/register")
api.add_resource(ClothesResource, "/clothes")


if __name__ == '__main__':
    app.run(debug=True)
