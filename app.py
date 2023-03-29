from flask import Flask, jsonify, request, json, make_response
from flask_restful import Resource, Api, reqparse, marshal_with, fields
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from marshmallow import Schema, fields, validate
from flask_restx import Namespace, Api
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required, current_user, login_manager,LoginManager, UserMixin
from flask_httpauth import HTTPBasicAuth
from functools import wraps
import datetime
from datetime import timedelta
from decouple import config
from flask_jwt_extended import jwt_required, create_access_token, create_refresh_token, JWTManager, get_jwt_identity
import jwt
import uuid
from flask_login import LoginManager


"""INITIALISE APP, DB, LOGIN MANAGER"""

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['SECRET_KEY'] = 'secret'
app.config['JWT_SECRET_KEY'] = 'secret-key'
# JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=30)
# JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=14)
db = SQLAlchemy(app)
ma = Marshmallow(app)
auth = HTTPBasicAuth()
authorizations = {
    'Bearer Auth': {
        'type': 'apiKey',
        'in': 'header',
        'name': 'Authorization',
        "description": "Add a JWT token to the header with ** Bearer &lt;JWT&gt; ** token to authorize user "
    }
}
api = Api(
    app,
    title='Student Management API',
    description='A student management API for managing student records with provided access to admin and students.\n'
    'The API is built with Python, Flask and Flask-RESTX and is still under development.\n'
    'Follow the steps below to use the API:\n'
    '1. Create a user account\n'
    '2. Login to generate a JWT token\n'
    '3. Add the token to the Authorization header with the Bearer prefix eg "Bearer JWT-token"\n'
    '4. Use the token to access the endpoints',
    authorizations=authorizations,
    security="Bearer Auth"
)

# jwt = JWTManager(app)

# Initialize the login manager
# login_manager = LoginManager()
# login_manager.init_app(app)


# SECRET_KEY = config('SECRET_KEY', 'secret')
# JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=30)
# JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=14)
# JWT_SECRET_KEY = config('JWT_SECRET_KEY')

# jwt = jwt_manager(app)

"""CREATE MODELS"""

#User model for authentication
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    name = db.Column(db.String(80))
    email = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean)
    # admin = db.Column(db.Boolean)

    def __repr__(self):
        return f"User(id={self.id}, username='{self.username}', email='{self.email}')"

#Student model
class Student(db.Model):
    __tablename__ = 'student'
    id = db.Column(db.Integer, primary_key=True)
    user = db.Column(db.Integer, db.ForeignKey('user.id'))
    # user_id = db.Column(db.Integer)
    # course = db.relationship('Course', secondary='student_course', lazy=True)
    # grade = db.relationship('Grade', backref='student_grade', lazy=True)

    def __repr__(self):
        return f"Student(id={self.id}, name='{self.name}', email='{self.email}', grade='{self.grade})"

class Admin(db.Model):
    __tablename__ = 'admin'
    id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)

#Course model
class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(50), nullable=False)
    code = db.Column(db.String(10), nullable=False)
    teacher = db.Column(db.Text)

    def __repr__(self):
        return f"Course(id={self.id}, title='{self.title}', code='{self.code}', teacher='{self.teacher}')"

# class Grade(db.Model):
#     id = db.Column(db.Integer(), primary_key=True)
#     student_id = db.Column(db.Integer(), db.ForeignKey('student.id'))
#     course_id = db.Column(db.Integer(), db.ForeignKey('course.id'))
#     percent_grade = db.Column(db.Float(), nullable=False)
#     letter_grade = db.Column(db.String(5), nullable=True)

#     def __repr__(self):
#         return f"Grade(id='{self.id}', student_id='{self.student_id}', course_id='{self.course_id}', percent_grade='{self.percent_grade}', letter_grade='{self.letter_grade}')"

#Enrollment model for the student-course relationship
class Enrollment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('student.id'), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=False)
    grade = db.Column(db.Integer)

    def __repr__(self):
        return f"Enrollment(id={self.id}, student_id={self.student_id}, course_id={self.course_id}, grade={self.grade})"



"""CREATE DB FILE"""

with app.app_context():
    db.create_all()



"""CREATE SCHEMA"""

#Authentication Schema
class SignUpSchema(ma.Schema):
    class Meta:
        fields = ("username", "email", "password")

signup_schema = SignUpSchema()

class LoginSchema(ma.Schema):
    class Meta:
        fields = ("username", "password")

login_schema = LoginSchema()

class UserSchema(ma.Schema):
    class Meta:
        model = User
        fields = ('id', 'public_id', 'username', 'name', 'email', 'is_admin')

class StudentSchema(ma.Schema):
    class Meta:
        model = Student
        fields = ('id', 'user')

    user = fields.Nested(UserSchema())


student_schema = StudentSchema()
students_schema = StudentSchema(many=True)

class CourseSchema(ma.Schema):
    class Meta:
        fields = ("id", "title", "code", "teacher")

course_schema = CourseSchema()
courses_schema = CourseSchema(many=True)

# class GradeSchema(ma.Schema):
#     class Meta:
#         fields = ("id", "student_id", "course_id", "percent_grade", "letter_grade")

# grade_schema = GradeSchema()
# grades_schema = GradeSchema(many=True)

class EnrollmentSchema(ma.Schema):
    class Meta:
        fields = ("id", "student_id", "course_id", "grade")

enrollment_schema = EnrollmentSchema()
enrollments_schema = EnrollmentSchema(many=True)



def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        print("x-access-token in request.headers================",'x-access-token' in request.headers)

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
            print("TOKEN==================", token)

        if not token:
            return jsonify(data={'message' : 'Token is missing!'}, status=401)

        try: 
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
            request.current_user = current_user
        except:
            return jsonify(data={'message' : 'Token is invalid!'}, status=401)

        return f(*args, **kwargs)

    return decorated

# def token_required(f):
#     @wraps(f)
#     def decorated(*args, **kwargs):
#         token = None

#         if 'Authorization' in request.headers:
#             token = request.headers['Authorization'].split(' ')[1]

#         if not token:
#             return jsonify({'message' : 'Token is missing!'}), 401

#         try:
#             data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
#             current_user = User.query.filter_by(public_id=data['public_id']).first()
#         except:
#             return jsonify({'message' : 'Token is invalid!'}), 401

#         return f(current_user, *args, **kwargs)

#     return decorated


# def token_required(app):
#     def decorator(f):
#         @wraps(f)
#         def decorated_function(*args, **kwargs):
#             token = None

#             if 'Authorization' in request.headers:
#                 token = request.headers['Authorization'].split()[1]

#             if not token:
#                 return jsonify({'message': 'Token is missing!'}), 401

#             try:
#                 data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
#                 current_user = User.query.filter_by(public_id=data['public_id']).first()
#             except:
#                 return jsonify({'message': 'Token is invalid!'}), 401

#             return f(current_user, *args, **kwargs)
#         return decorated_function
#     return decorator



"""AUTHENTICATION PROPER"""

class SignUpList(Resource):
    def get(self):
        """ retrieves all users """
        users = User.query.all()
        output = []
        for user in users:
            user_data = {}
            user_data['public_id'] = user.public_id
            user_data['username'] = user.username
            user_data['password'] = user.password
            user_data['is_admin'] = user.is_admin
            output.append(user_data)
        return jsonify({'users': output})

    def post(self):
        """ creates new user """
        data = request.get_json()
        hashed_password = generate_password_hash(data['password'], method='sha256')
        new_user = User(public_id=str(uuid.uuid4()), username=data['username'], email=data['email'], password=hashed_password, is_admin=False)
        db.session.add(new_user)
        db.session.commit()
        return signup_schema.dump(new_user)

class SignUpDetail(Resource):
    def get(self, public_id):
        """ retrieves user by id """
        user = User.query.filter_by(public_id=public_id).first()
        if not user:
            return jsonify({'message':'User not found!'})
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['username'] = user.username
        user_data['password'] = user.password
        user_data['admin'] = user.admin

        return jsonify({'user':user_data})

    def put(self, public_id):
        """ updates admin status """
        user = User.query.filter_by(public_id=public_id).first()
        if not user:
            return jsonify({'message':'User not found!'})
        user.admin = True
        db.session.commit()

        return jsonify({'message':'User promoted successfully!'})

    def delete(self, public_id):
        """ deletes user """
        user = User.query.filter_by(public_id=public_id).first()
        if not user:
            return make_response('User does not exist', 401)
        db.session.delete(user)
        db.session.commit()
        return '', 204

class Login(Resource):
    def post(self):
        auth = request.authorization
        if not auth or not auth.username or not auth.password:
            return make_response('Could not verify user', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})
        user = User.query.filter_by(username=auth.username).first()
        if not user:
            return make_response('Could not verify user', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})
        if check_password_hash(user.password, auth.password):
            if not app.config.get('SECRET_KEY') or not isinstance(app.config['SECRET_KEY'], str):
                return make_response('Invalid app secret key', 500)
            token = jwt.encode({'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'], algorithm='HS256')
            return jsonify({'token': token})
        return make_response('Could not verify user', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

        # username = request.json('username', '')
        # password = request.json('password', '')
        # user = User.query.filter_by(username=username).first()
        # if user:
        #     is_password_correct = check_password_hash(user.password, password)
        #     if is_password_correct:
        #         refresh = create_refresh_token(identity=user.id)
        #         access = create_access_token(identity=user.id)
        #         return jsonify({'user':{'refresh':refresh,'access':access,'username':user.username,'email':user.email}})
        # return jsonify({'error':'Invalid credentials'}), 401


class StudentList(Resource):
    @token_required
    def get(self):
        """ retrieves all students """
        # if not current_user.admin:
        #     return jsonify({'message' : 'Cannot perform that function!'})

        # students = Student.query.filter_by(user_id=current_user.id).all()
        students = Student.query.all()
        return students_schema.dump(students)

    def post(self):
        """ creates new student """
        new_user = User(
            name=request.json['name'],
            username=request.json['username'],
            email=request.json['email'],
            password=request.json['password'],
        )
        db.session.add(new_user)
        db.session.commit()

        new_student = Student(user=new_user.id)
        db.session.add(new_student)
        db.session.commit()
        print("It created!!!!!!!")
        return student_schema.dump(new_student)

class StudentDetail(Resource):
    def get(self, student_id):
        """ retrieves student by id """
        student = Student.query.get_or_404(student_id)
        return student_schema.dump(student)

    @token_required
    def put(self, student_id):
        if not request.current_user.is_admin:
            return jsonify(data={"error": "Permission Denied"}, status=401)
        
        student = Student.query.get_or_404(student_id)
        """ updates student details """
        if 'name' in request.json:
            student.name = request.json['name']
        if 'email' in request.json:
            student.email = request.json['email']
        db.session.commit()
        return student_schema.dump(student)

    # @verify_token
    def delete(self, student_id):
        """ deletes a particular student """
        student = Student.query.get_or_404(student_id)
        db.session.delete(student)
        db.session.commit()
        return '', 204


class CourseList(Resource):
    
    def get(self):
        """ retrieves all courses """
        courses = Course.query.all()
        return courses_schema.dump(courses)

    def post(self):
        """ creates a new course """
        new_course = Course(
            name=request.json['title'],
            code=request.json['code'],
            description=request.json['teacher']
            )
        db.session.add(new_course)
        db.session.commit()
        return course_schema.dump(new_course)

class CourseDetail(Resource):
    def get(self, course_id):
        """ retrieves course by id """
        course = Course.query.get_or_404(course_id)
        return course_schema.dump(course)

    def put(self, course_id):
        course = Course.query.get_or_404(course_id)
        """ updates course details """
        if 'title' in request.json:
            course.title = request.json['title']
        if 'code' in request.json:
            course.code = request.json['code']
        if 'teacher' in request.json:
            course.teacher = request.json['teacher']
        db.session.commit()
        return course_schema.dump(course)

    # @verify_token
    def delete(self, course_id):
        """ deletes a particular course """
        course = Course.query.get_or_404(course_id)
        db.session.delete(course)
        db.session.commit()
        return '', 204
      
class CourseStudentsList(Resource):
     def get(self, course_id):
        """ Returns the list of students registerd in a course """
        enrollments = Enrollment.query.filter(Enrollment.course_id == course_id).all()
        student_ids = [enrollment.student_id for enrollment in enrollments]
        students = Student.query.filter(Student.id.in_(student_ids)).all()
        return students_schema.dump(students)


class EnrollmentList(Resource):
      def get(self):
            """ retrieves enrollment list """
            enrollments = Enrollment.query.all()
            return enrollments_schema.dump(enrollments)

      def post(self):
            """ creates new enrollment """
            new_enrollment = Enrollment(student_id=request.json['student_id'],
            course_id=request.json['course_id'], grade=request.json['grade'])
            db.session.add(new_enrollment)
            db.session.commit()
            return enrollment_schema.dump(new_enrollment), 201

class EnrollmentDetail(Resource):
      def get(self, course_id):
            """ returns specific enrollment details """
            enrollment = Enrollment.query.get_or_404(course_id)
            return enrollment_schema.dump(enrollment)

      def put(self, enrollment_id):
            """ updates enrollment details by id """
            enrollment = Enrollment.query.get_or_404(enrollment_id)
            if 'grade' in request.json:
                  enrollment.grade = request.json['grade']
            db.session.commit()
            return enrollment_schema.dump(enrollment)

      def delete(self, enrollment_id):
            """ deletes specific enrollment """
            enrollment = Enrollment.query.get_or_404(enrollment_id)
            db.session.delete(enrollment)
            db.session.commit()
            return '', 204


# class GetAddUpdateGrades(Resource):
#     def get(self, student_id):
#         """
#             Retrieve a Student's Grades - Admins or Specific Student Only
#         """

#         # Confirm existence of student
#         student = Student.query.filter_by(id=student_id).first()
#         if not student:
#             return {"message": "Student Not Found"}
            
        # Retrieve the student's grades        
        # courses = StudentCourse.get_courses_by_student(student_id)
        # resp = []

        # for course in courses:
        #     grade_resp = {}
        #     grade_in_course = Grade.query.filter_by(student_id=student_id, course_id=course.id).first()
        #     grade_resp['course_name'] = course.name

        #     if grade_in_course:
        #         grade_resp['grade_id'] = grade_in_course.id
        #         grade_resp['percent_grade'] = grade_in_course.percent_grade
        #         grade_resp['letter_grade'] = grade_in_course.letter_grade
        #     else:
        #         grade_resp['percent_grade'] = None
        #         grade_resp['letter_grade'] = None
                
        #         resp.append(grade_resp)
            
        #     return resp
        
        # else:
        #     return {"message": "Admins or Specific Student Only"}
        



#     def post(self, student_id):
#         """
#             Upload a Student's Grade in a Course - Admins Only
#         """
#         data = student_namespace.payload

#         student = Student.get_by_id(student_id)
#         course = Course.get_by_id(id=data['course_id'])
        
#         # Confirm that the student is taking the course
#         student_course = StudentCourse.query.filter_by(student_id=student_id, course_id=course.id).first()
#         if not student_course:
#             return {"message": f"{student.first_name} {student.last_name} is not taking {course.name}"}
        
#         # Add a new grade
#         new_grade = Grade(
#             student_id = student_id,
#             course_id = data['course_id'],
#             percent_grade = data['percent_grade'],
#             letter_grade = get_letter_grade(data['percent_grade'])
#         )

#         new_grade.save()

#         grade_resp = {}
#         grade_resp['grade_id'] = new_grade.id
#         grade_resp['student_id'] = new_grade.student_id
#         grade_resp['student_first_name'] = student.first_name
#         grade_resp['student_last_name'] = student.last_name
#         grade_resp['student_matric_no'] = student.matric_no
#         grade_resp['course_id'] = new_grade.course_id
#         grade_resp['course_name'] = course.name
#         grade_resp['course_teacher'] = course.teacher
#         grade_resp['percent_grade'] = new_grade.percent_grade
#         grade_resp['letter_grade'] = new_grade.letter_grade

#         return grade_resp
        


# class UpdateDeleteGrade(Resource):
#     def put(self, grade_id):
#         """
#             Update a Grade - Admins Only
#         """
#         data = student_namespace.payload

#         grade = Grade.get_by_id(grade_id)
        
#         grade.percent_grade = data['percent_grade']
#         grade.letter_grade = get_letter_grade(data['percent_grade'])
        
#         grade.update()

#         grade_resp = {}
#         grade_resp['grade_id'] = grade.id
#         grade_resp['student_id'] = grade.student_id
#         grade_resp['course_id'] = grade.course_id
#         grade_resp['percent_grade'] = grade.percent_grade
#         grade_resp['letter_grade'] = grade.letter_grade

#         return grade_resp
    

#     def delete(self, grade_id):
#         """
#             Delete a Grade - Admins Only
#         """
#         grade = Grade.get_by_id(grade_id)
        
#         grade.delete()

#         return {"message": "Grade Successfully Deleted"}
        
    

# class GetStudentCGPA(Resource):


#     def get(self, student_id):
#         """
#             Calculate a Student's CGPA - Admins or Specific Student Only
#         """
#         if is_student_or_admin(student_id):

#             student = Student.get_by_id(student_id)
            
#             courses = StudentCourse.get_courses_by_student(student_id)
#             total_gpa = 0
            
#             for course in courses:
#                 grade = Grade.query.filter_by(
#                         student_id=student_id, course_id=course.id
#                     ).first()
                
#                 if grade:
#                     letter_grade = grade.letter_grade
#                     gpa = convert_grade_to_gpa(letter_grade)
#                     total_gpa += gpa
                
#             cgpa = total_gpa / len(courses)
#             round_cgpa = float("{:.2f}".format(cgpa))

#             return {"message": f"{student.first_name} {student.last_name}'s CGPA is {round_cgpa}"}
    
#         else:
#             return {"message": "Admins or Specific Student Only"}






api.add_resource(SignUpList, '/students/signup')
api.add_resource(SignUpDetail, '/students/signup/<public_id>')
# api.add_resource(Signup, '/students/signup')
api.add_resource(Login, '/students/login')
api.add_resource(StudentList, '/students')
api.add_resource(StudentDetail, '/students/<int:student_id>')
api.add_resource(CourseList, '/courses')
api.add_resource(CourseDetail, '/courses/<int:course_id>')
api.add_resource(CourseStudentsList, '/courses/<int:course_id>/students')
api.add_resource(EnrollmentList, '/enrollments')
api.add_resource(EnrollmentDetail, '/enrollments/<int:course_id>')



if __name__ == '__main__':
    app.run(debug=True)