# student-app
# A Simple School Management System API Built with Flask, Flask_RestX
---
## Table of Contents
- [Introduction](#introduction)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Contributing](#contributing)
- [Live Demo](#live-demo)
- [Upcoming Features](#upcoming-features)
- [License](#license)

## Introduction
This is a simple school management system API built with Flask and Flask_RestX built by according to [this requirements](https://docs.google.com/document/d/19ayXN5P1oV2aqW_7-As6EUpn7OQShkpAlZK4wRbrgBQ/). It is a simple API that allows you if you are an Admin to perform CRUD operations on students and courses. It also allows you to register students to courses and add grade for students.

## Features
- Admin can create, read, update and delete students and courses
- Admin can register and unregister students to courses
- Admin can add grade for students
- Admin can view all students and courses
- Admin can view all students registered to a course
- Admin can view all courses a student is registered to
- User/Student can view all courses he/she is registered to and the grade he/she got for each course
- User/Student can Register to a course
- User/Student can Unregister from a course
- User/Studet can view and update his/her details

## Installation
- Clone the repository
- Create a virtual environment `python3 -m venv venv` or with `virtualenv venv`
- Install the requirements `pip install -r requirements.txt`
- Run the application `python3 runserver.py`
- Initialize the database `Flask --app api db init`


## Usage
- To run the application, run `python3 runserver.py`
- To run the tests, run `python3 -m pytest`
- To Create an Admin, run `Flask --app api create-admin-command` then put the admin Username and Password
- To Active the Admin, run `Flask --app api activate-admin-command` then put the admin Username 
- To Deactivate the Admin, run `Flask --app api deactivate-admin-command` then put the admin Username
- To Delete the Admin, run `Flask --app api delete-admin-command` then put the admin Username

## Contributing
- Fork the repository
- Clone the repository
- Create a virtual environment `python3 -m venv venv` or with `virtualenv venv`
- Install the requirements `pip install -r requirements.txt`
- Create a new branch `git checkout -b new-branch`
- Make your changes
- Commit your changes `git commit -m "commit message"`
- Push to the branch `git push origin new-branch`
- Create a pull request

## Live Demo
- [PythonAnywhere](https://jurrasic5.pythonanywhere.com/)

## Upcoming Features
- Add more tests / Improve tests (some tests are failing)
- Add more features to the API
- Add more documentation to the API
- Add more features to the Admin dashboard
- Update to Postgres database instead of SQLite for production

## License
[MIT](https://github.com/Digitalguyco/Flask_Sch_mgt/blob/master/LICENCE)
