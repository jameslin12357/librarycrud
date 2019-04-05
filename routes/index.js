var express = require('express');
var router = express.Router();
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var { body,validationResult } = require('express-validator/check');
var { sanitizeBody } = require('express-validator/filter');
var bcrypt = require('bcryptjs');
var saltRounds = 10;
var moment = require('moment');
var mysql = require('mysql');

// Middlewares
function isNotAuthenticated(req, res, next) {
    if (!(req.isAuthenticated())){
        return next();
    }
    res.redirect('/403');
}

function isAuthenticated(req, res, next) {
    if (req.isAuthenticated()){
        return next();
    }
    res.redirect('/login');
}

// extract word after first slash and word after second slash
function isResource(req, res, next) {
    let uri = req._parsedOriginalUrl.path;
    if (uri.includes('/api')){
        uri = uri.substring(4);
    }
    if (uri.includes('?')){
        uri = uri.substring(0, uri.indexOf("?"));
    }
    uri = uri.substring(1);
    uri = uri.substring(0, uri.indexOf('/'));
    // let table = uri.substring(0, uri.length - 1);
    let table = uri;
    let id = Number(req.params.id);
    let connection = mysql.createConnection({
        host     : process.env.DB_HOSTNAME,
        user     : process.env.DB_USERNAME,
        password : process.env.DB_PASSWORD,
        port     : process.env.DB_PORT,
        database : process.env.DB_NAME,
        multipleStatements: true
    });
    connection.query('SELECT id FROM ' + table + ' WHERE id = ?', [id], function(error, results, fields) {
        // error will be an Error if one occurred during the query
        // results will contain the results of the query
        // fields will contain information about the returned results fields (if any)
        if (error) {
            throw error;
        }
        if (results.length === 0){
            res.render('404');
        }
        else {
            next();
        }
    });
}

// function isOwnResource(req, res, next) {
//     let uri = req._parsedOriginalUrl.path;
//     uri = uri.substring(1);
//     uri = uri.substring(0, uri.lastIndexOf('/'));
//     if (uri.includes('/')){
//         uri = uri.substring(0, uri.lastIndexOf('/'));
//     }
//     uri = uri.substring(0, uri.length - 1);
//     let table = uri;
//     let resourceid = req.params.id;
//     if (table === 'user') {
//         if (req.user.id !== Number(resourceid)) {
//             res.render('403');
//         } else {
//             next();
//         }
//     } else {
//         var connection = mysql.createConnection({
//             host     : process.env.DB_HOSTNAME,
//             user     : process.env.DB_USERNAME,
//             password : process.env.DB_PASSWORD,
//             port     : process.env.DB_PORT,
//             database : process.env.DB_NAME,
//             multipleStatements: true
//         });
//         connection.query('SELECT userid FROM ' + table + ' WHERE id = ?', [resourceid], function (error, results, fields) {
//             // error will be an Error if one occurred during the query
//             // results will contain the results of the query
//             // fields will contain information about the returned results fields (if any)
//             if (error) {
//                 throw error;
//             }
//             if (req.user.id !== results[0].userid) {
//                 res.render('403');
//             } else {
//                 next();
//             }
//         });
//     }
// }

/* GET home page. */
// if user is logged in return feed page else return home page
router.get('/', function(req, res, next) {
  if (req.isAuthenticated()) {
      connection.query('SELECT * FROM addresses ORDER BY date_created DESC; SELECT count(*) as count FROM addresses',
          function (error, results, fields) {
              if (error) {
                  throw error;
              }
              res.render('addresses/index', {
                  title: 'Addresses',
                  req: req,
                  results: results,
                  alert: req.flash('alert')
              });
          }
      );
  } else {
      res.redirect('/login');
  }
});

// USER ROUTES
router.get('/users/new', isNotAuthenticated, function(req, res, next){
    res.render('users/new', {
        title: 'Sign up',
        req: req,
        errors: req.flash('errors'),
        inputs: req.flash('inputs')
    });
});

// validate user input and if wrong redirect to register page with errors and inputs else save data into
// database and redirect to login with flash message
router.post('/users', isNotAuthenticated, [
    body('email', 'Empty email.').not().isEmpty(),
    body('password', 'Empty password.').not().isEmpty(),
    body('username', 'Empty username.').not().isEmpty(),
    body('email', 'Email must be between 5-200 characters.').isLength({min:5, max:200}),
    body('password', 'Password must be between 5-60 characters.').isLength({min:5, max:60}),
    body('username', 'Username must be between 5-200 characters.').isLength({min:5, max:200}),
    body('email', 'Invalid email.').isEmail(),
    body('password', 'Password must contain one lowercase character, one uppercase character, a number, and ' +
        'a special character.').matches(/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?!.* )(?=.*[^a-zA-Z0-9]).{8,}$/, "i")
], function(req, res, next){
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        req.flash('errors', errors.array());
        req.flash('inputs', {email: req.body.email, username: req.body.username});
        res.redirect('/users/new');
    }
    else {
        sanitizeBody('email').trim().escape();
        sanitizeBody('password').trim().escape();
        sanitizeBody('username').trim().escape();
        const email = req.body.email;
        const password = req.body.password;
        const username = req.body.username;
        bcrypt.hash(password, saltRounds, function(err, hash) {
            // Store hash in your password DB.
            if (err) {
                throw error;
            }
            connection.query('INSERT INTO users (email, username, password) VALUES (?, ?, ?)',
                [email, username, hash], function (error, results, fields) {
                    // error will be an Error if one occurred during the query
                    // results will contain the results of the query
                    // fields will contain information about the returned results fields (if any)
                    if (error) {
                        throw error;
                    }
                    req.flash('alert', 'You have successfully registered.');
                    res.redirect('/login');
                });
        });
    }
});

router.get('/users/:id', isResource, isAuthenticated, function(req, res){
    connection.query('SELECT id, email, username, description, imageurl, datecreated, level FROM users WHERE id = ?',
        [req.params.id],
        function (error, results, fields) {
            // error will be an Error if one occurred during the query
            // results will contain the results of the query
            // fields will contain information about the returned results fields (if any)
            if (error) {
                throw error;
            }
            console.log(results);
            res.render('users/show', {
                                title: 'Profile',
                                req: req,
                                results: results,
                                moment: moment,
                                alert: req.flash('alert')
                            });
        });
});

router.get('/users/:id/edit', isResource, isAuthenticated, function(req, res){
    if (req.user.id === Number(req.params.id)){
        connection.query('SELECT id, email, username, description FROM users WHERE id = ?', [req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                res.render('users/edit', {
                    title: 'Edit profile',
                    req: req,
                    results: results,
                    errors: req.flash('errors'),
                    inputs: req.flash('inputs')
                });
            });
    } else {
        res.render('403');
    }
});

router.put('/users/:id', isResource, isAuthenticated, function(req, res, next){
    if (req.user.id === Number(req.params.id)){
        next();
    } else {
        res.render('403');
    }
}, [
    body('email', 'Empty email.').not().isEmpty(),
    body('username', 'Empty username.').not().isEmpty(),
    body('description', 'Empty description.').not().isEmpty(),
    body('email', 'Email must be between 5-200 characters.').isLength({min:5, max:200}),
    body('username', 'Username must be between 5-200 characters.').isLength({min:5, max:200}),
    body('description', 'Description must be between 5-200 characters.').isLength({min:5, max:200}),
    body('email', 'Invalid email.').isEmail()
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        req.flash('errors', errors.array());
        req.flash('inputs', {email: req.body.email, username: req.body.username, description: req.body.description});
        res.redirect(req._parsedOriginalUrl.pathname + '/edit');
    }
    else {
        sanitizeBody('email').trim().escape();
        sanitizeBody('username').trim().escape();
        sanitizeBody('description').trim().escape();
        const email = req.body.email;
        const username = req.body.username;
        const description = req.body.description;
        connection.query('UPDATE users SET email = ?, username = ?, description = ? WHERE id = ?',
            [email, username, description, req.params.id], function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Profile edited.');
                res.redirect(req._parsedOriginalUrl.pathname);
            });
    }
});

router.delete('/users/:id', isResource, isAuthenticated, function(req, res, next){
    if (req.user.id === Number(req.params.id)){
        next();
    } else {
        res.render('403');
    }
}, function(req, res){
    connection.query('DELETE FROM users WHERE id = ?', [req.params.id], function (error, results, fields) {
        // error will be an Error if one occurred during the query
        // results will contain the results of the query
        // fields will contain information about the returned results fields (if any)
        if (error) {
            throw error;
        }
        req.flash('alert', 'Profile deleted.');
        req.logout();
        res.redirect('/');
    });
});


// address routes
router.get('/addresses/new', isAuthenticated, function(req, res){
    if (req.user.level === 1){
        res.render('addresses/new', {
            title: 'Create',
            req: req,
            errors: req.flash('errors'),
            inputs: req.flash('inputs')
        });
    } else {
        res.render('403');
    }
});

router.post('/addresses', isAuthenticated, function(req, res, next) {
        if (req.user.level === 1){
            return next();
        } else {
            res.render('403');
        }
},[
            body('building_number', 'Empty building number.').not().isEmpty(),
            body('street', 'Empty street.').not().isEmpty(),
            body('city', 'Empty city.').not().isEmpty(),
            body('state', 'Empty state.').not().isEmpty(),
            body('country', 'Empty country.').not().isEmpty(),
            body('zip', 'Empty zip.').not().isEmpty(),
            body('building_number', 'Building number must be between 5-100 characters.').isLength({min:5, max:100}),
            body('street', 'Street must be between 5-100 characters.').isLength({min:5, max:100}),
            body('city', 'City must be between 5-100 characters.').isLength({min:5, max:100}),
            body('state', 'State must be between 5-100 characters.').isLength({min:5, max:100}),
            body('country', 'Country must be between 5-100 characters.').isLength({min:5, max:100}),
            body('zip', 'Zip must be between 1-5 characters.').isLength({min:1, max:5}),
        ]
    , (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            req.flash('errors', errors.array());
            req.flash('inputs', {building_number: req.body.building_number, street: req.body.street, city: req.body.city,
                state: req.body.state, country: req.body.country, zip: req.body.zip});
            res.redirect('/addresses/new');
        }
        else {
            sanitizeBody('building_number').trim().escape();
            sanitizeBody('street').trim().escape();
            sanitizeBody('city').trim().escape();
            sanitizeBody('state').trim().escape();
            sanitizeBody('country').trim().escape();
            sanitizeBody('zip').trim().escape();
            const building_number = req.body.building_number;
            const street = req.body.street;
            const city = req.body.city;
            const state = req.body.state;
            const country = req.body.country;
            const zip = req.body.zip;
            connection.query('INSERT INTO addresses (building_number, street, city, state, country, zip) VALUES ' +
                '(?, ?, ?, ?, ?, ?)', [building_number, street, city, state, country, zip], function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Address created.');
                res.redirect('/');
            });
        }
    }
);

router.get('/addresses/:id/edit', isResource, isAuthenticated, function(req, res) {
    if (req.user.level === 1){
        connection.query('SELECT id, building_number, street, city, state, country, zip FROM addresses WHERE id = ?', [req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                res.render('addresses/edit', {
                    title: 'Edit address',
                    req: req,
                    results: results,
                    errors: req.flash('errors'),
                    inputs: req.flash('inputs')
                });
            });
    } else {
        res.render('403');
    }

});

router.put('/addresses/:id', isResource, isAuthenticated, function(req, res, next) {
        if (req.user.level === 1){
            return next();
        } else {
            res.render('403');
        }
}, [
    body('building_number', 'Empty building number.').not().isEmpty(),
    body('street', 'Empty street.').not().isEmpty(),
    body('city', 'Empty city.').not().isEmpty(),
    body('state', 'Empty state.').not().isEmpty(),
    body('country', 'Empty country.').not().isEmpty(),
    body('zip', 'Empty zip.').not().isEmpty(),
    body('building_number', 'Building number must be between 5-100 characters.').isLength({min:5, max:100}),
    body('street', 'Street must be between 5-100 characters.').isLength({min:5, max:100}),
    body('city', 'City must be between 5-100 characters.').isLength({min:5, max:100}),
    body('state', 'State must be between 5-100 characters.').isLength({min:5, max:100}),
    body('country', 'Country must be between 5-100 characters.').isLength({min:5, max:100}),
    body('zip', 'Zip must be between 1-5 characters.').isLength({min:1, max:5}),
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        // There are errors. Render form again with sanitized values/errors messages.
        // Error messages can be returned in an array using `errors.array()`.
        req.flash('errors', errors.array());
        req.flash('inputs', {building_number: req.body.building_number, street: req.body.street, city: req.body.city,
            state: req.body.state, country: req.body.country, zip: req.body.zip});
        res.redirect(req._parsedOriginalUrl.pathname + '/edit');
    }
    else {
        sanitizeBody('building_number').trim().escape();
        sanitizeBody('street').trim().escape();
        sanitizeBody('city').trim().escape();
        sanitizeBody('state').trim().escape();
        sanitizeBody('country').trim().escape();
        sanitizeBody('zip').trim().escape();
        const building_number = req.body.building_number;
        const street = req.body.street;
        const city = req.body.city;
        const state = req.body.state;
        const country = req.body.country;
        const zip = req.body.zip;
        connection.query('UPDATE addresses SET building_number = ?, street = ?, city = ?, state = ?,' +
            'country = ?, zip = ? WHERE id = ?',
            [building_number, street, city, state, country, zip, req.params.id], function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Address edited.');
                res.redirect('/');
            });
    }
});

router.delete('/addresses/:id', isResource, isAuthenticated, function(req, res, next) {
        if (req.user.level === 1){
            connection.query('DELETE FROM addresses WHERE id = ?', [req.params.id], function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Address deleted.');
                res.redirect('/');
            });
        } else {
            res.render('403');
        }
        });

// author routes
router.get('/authors', function(req, res, next) {
    if (req.isAuthenticated()) {
        connection.query('SELECT * FROM authors ORDER BY date_created DESC; SELECT count(*) as count FROM authors',
            function (error, results, fields) {
                if (error) {
                    throw error;
                }
                res.render('authors/index', {
                    title: 'Authors',
                    req: req,
                    results: results,
                    alert: req.flash('alert')
                });
            }
        );
    } else {
        res.redirect('/login');
    }
});

router.get('/authors/new', isAuthenticated, function(req, res){
    if (req.user.level === 1){
        res.render('authors/new', {
            title: 'Create',
            req: req,
            errors: req.flash('errors'),
            inputs: req.flash('inputs')
        });
    } else {
        res.render('403');
    }
});

router.post('/authors', isAuthenticated, function(req, res, next) {
        if (req.user.level === 1){
            return next();
        } else {
            res.render('403');
        }
    },[
        body('first_name', 'Empty first name.').not().isEmpty(),
        body('last_name', 'Empty last name.').not().isEmpty(),
        body('age', 'Empty age.').not().isEmpty(),
        body('first_name', 'First Name must be between 5-100 characters.').isLength({min:5, max:100}),
        body('last_name', 'Last Name must be between 5-100 characters.').isLength({min:5, max:100}),
    ]
    , (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            req.flash('errors', errors.array());
            req.flash('inputs', {first_name: req.body.first_name, last_name: req.body.last_name, age: req.body.age
                });
            res.redirect('/authors/new');
        }
        else {
            sanitizeBody('first_name').trim().escape();
            sanitizeBody('last_name').trim().escape();
            sanitizeBody('age').trim().escape();
            const first_name = req.body.first_name;
            const last_name = req.body.last_name;
            const age = req.body.age;
            connection.query('INSERT INTO authors (fname, lname, age) VALUES ' +
                '(?, ?, ?)', [first_name, last_name, age], function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Author created.');
                res.redirect('/authors');
            });
        }
    }
);

router.get('/authors/:id/edit', isResource, isAuthenticated, function(req, res) {
    if (req.user.level === 1){
        connection.query('SELECT id, fname, lname, age FROM authors WHERE id = ?', [req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                res.render('authors/edit', {
                    title: 'Edit author',
                    req: req,
                    results: results,
                    errors: req.flash('errors'),
                    inputs: req.flash('inputs')
                });
            });
    } else {
        res.render('403');
    }

});

router.put('/authors/:id', isResource, isAuthenticated, function(req, res, next) {
    if (req.user.level === 1){
        return next();
    } else {
        res.render('403');
    }
}, [
    body('first_name', 'Empty first name.').not().isEmpty(),
    body('last_name', 'Empty last name.').not().isEmpty(),
    body('age', 'Empty age.').not().isEmpty(),
    body('first_name', 'First Name must be between 5-100 characters.').isLength({min:5, max:100}),
    body('last_name', 'Last Name must be between 5-100 characters.').isLength({min:5, max:100}),
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        // There are errors. Render form again with sanitized values/errors messages.
        // Error messages can be returned in an array using `errors.array()`.
        req.flash('errors', errors.array());
        req.flash('inputs', {first_name: req.body.first_name, last_name: req.body.last_name, age: req.body.age});
        res.redirect(req._parsedOriginalUrl.pathname + '/edit');
    }
    else {
        sanitizeBody('first_name').trim().escape();
        sanitizeBody('last_name').trim().escape();
        sanitizeBody('age').trim().escape();
        const first_name = req.body.first_name;
        const last_name = req.body.last_name;
        const age = req.body.age;
        connection.query('UPDATE authors SET fname = ?, lname = ?, age = ? WHERE id = ?',
            [first_name, last_name, age, req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Author edited.');
                res.redirect('/authors');
            });
    }
});

router.delete('/authors/:id', isResource, isAuthenticated, function(req, res, next) {
    if (req.user.level === 1){
        connection.query('DELETE FROM authors WHERE id = ?', [req.params.id], function (error, results, fields) {
            // error will be an Error if one occurred during the query
            // results will contain the results of the query
            // fields will contain information about the returned results fields (if any)
            if (error) {
                throw error;
            }
            req.flash('alert', 'Author deleted.');
            res.redirect('/authors');
        });
    } else {
        res.render('403');
    }
});

// book routes
router.get('/books', function(req, res, next) {
    if (req.isAuthenticated()) {
        connection.query('SELECT * FROM books ORDER BY date_created DESC; SELECT count(*) as count FROM books',
            function (error, results, fields) {
                if (error) {
                    throw error;
                }
                res.render('books/index', {
                    title: 'Books',
                    req: req,
                    results: results,
                    alert: req.flash('alert')
                });
            }
        );
    } else {
        res.redirect('/login');
    }
});

router.get('/books/new', isAuthenticated, function(req, res){
    if (req.user.level === 1){
        res.render('books/new', {
            title: 'Create',
            req: req,
            errors: req.flash('errors'),
            inputs: req.flash('inputs')
        });
    } else {
        res.render('403');
    }
});

router.post('/books', isAuthenticated, function(req, res, next) {
        if (req.user.level === 1){
            return next();
        } else {
            res.render('403');
        }
    },[
        body('title', 'Empty title.').not().isEmpty(),
        body('description', 'Empty description.').not().isEmpty(),
        body('isbn', 'Empty isbn.').not().isEmpty(),
        body('length', 'Empty length.').not().isEmpty(),
        body('author_id', 'Empty author id.').not().isEmpty(),
        body('category_id', 'Empty category id.').not().isEmpty(),
        body('publisher_id', 'Empty publisher id.').not().isEmpty(),
        body('title', 'Title must be between 5-100 characters.').isLength({min:5, max:100})
    ]
    , (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            req.flash('errors', errors.array());
            req.flash('inputs', {title: req.body.title, description: req.body.description, isbn: req.body.isbn,
                length: req.body.length, author_id: req.body.author_id, category_id: req.body.category_id, publisher_id: req.body.publisher_id
            });
            res.redirect('/books/new');
        }
        else {
            sanitizeBody('title').trim().escape();
            sanitizeBody('description').trim().escape();
            sanitizeBody('isbn').trim().escape();
            sanitizeBody('length').trim().escape();
            sanitizeBody('author_id').trim().escape();
            sanitizeBody('category_id').trim().escape();
            sanitizeBody('publisher_id').trim().escape();
            const title = req.body.title;
            const description = req.body.description;
            const isbn = req.body.isbn;
            const length = req.body.length;
            const author_id = req.body.author_id;
            const category_id = req.body.category_id;
            const publisher_id = req.body.publisher_id;
            connection.query('INSERT INTO books (title, description, isbn, length, author_id, category_id, publisher_id) VALUES ' +
                '(?, ?, ?,?, ?, ?,?)', [title, description, isbn, length, author_id, category_id, publisher_id], function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Book created.');
                res.redirect('/books');
            });
        }
    }
);

router.get('/books/:id/edit', isResource, isAuthenticated, function(req, res) {
    if (req.user.level === 1){
        connection.query('SELECT id, title, description, isbn, length, author_id, category_id, publisher_id FROM books WHERE id = ?', [req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                res.render('books/edit', {
                    title: 'Edit book',
                    req: req,
                    results: results,
                    errors: req.flash('errors'),
                    inputs: req.flash('inputs')
                });
            });
    } else {
        res.render('403');
    }

});

router.put('/books/:id', isResource, isAuthenticated, function(req, res, next) {
    if (req.user.level === 1){
        return next();
    } else {
        res.render('403');
    }
}, [
    body('title', 'Empty title.').not().isEmpty(),
    body('description', 'Empty description.').not().isEmpty(),
    body('isbn', 'Empty isbn.').not().isEmpty(),
    body('length', 'Empty length.').not().isEmpty(),
    body('author_id', 'Empty author id.').not().isEmpty(),
    body('category_id', 'Empty category id.').not().isEmpty(),
    body('publisher_id', 'Empty publisher id.').not().isEmpty(),
    body('title', 'Title must be between 5-100 characters.').isLength({min:5, max:100})
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        // There are errors. Render form again with sanitized values/errors messages.
        // Error messages can be returned in an array using `errors.array()`.
        req.flash('errors', errors.array());
        req.flash('inputs', {title: req.body.title, description: req.body.description, isbn: req.body.isbn,
            length: req.body.length, author_id: req.body.author_id, category_id: req.body.category_id, publisher_id: req.body.publisher_id});
        res.redirect(req._parsedOriginalUrl.pathname + '/edit');
    }
    else {
        sanitizeBody('title').trim().escape();
        sanitizeBody('description').trim().escape();
        sanitizeBody('isbn').trim().escape();
        sanitizeBody('length').trim().escape();
        sanitizeBody('author_id').trim().escape();
        sanitizeBody('category_id').trim().escape();
        sanitizeBody('publisher_id').trim().escape();
        const title = req.body.title;
        const description = req.body.description;
        const isbn = req.body.isbn;
        const length = req.body.length;
        const author_id = req.body.author_id;
        const category_id = req.body.category_id;
        const publisher_id = req.body.publisher_id;
        connection.query('UPDATE books SET title = ?, description = ?, isbn = ?, length = ?, author_id = ?, category_id = ?, publisher_id = ? WHERE id = ?',
            [title, description, isbn, length, author_id, category_id, publisher_id, req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Book edited.');
                res.redirect('/books');
            });
    }
});

router.delete('/books/:id', isResource, isAuthenticated, function(req, res, next) {
    if (req.user.level === 1){
        connection.query('DELETE FROM books WHERE id = ?', [req.params.id], function (error, results, fields) {
            // error will be an Error if one occurred during the query
            // results will contain the results of the query
            // fields will contain information about the returned results fields (if any)
            if (error) {
                throw error;
            }
            req.flash('alert', 'Book deleted.');
            res.redirect('/books');
        });
    } else {
        res.render('403');
    }
});

// booklender routes
router.get('/bookslenders', function(req, res, next) {
    if (req.isAuthenticated()) {
        connection.query('SELECT * FROM bookslenders ORDER BY date_created DESC; SELECT count(*) as count FROM bookslenders',
            function (error, results, fields) {
                if (error) {
                    throw error;
                }
                res.render('bookslenders/index', {
                    title: 'Bookslenders',
                    req: req,
                    results: results,
                    alert: req.flash('alert')
                });
            }
        );
    } else {
        res.redirect('/login');
    }
});

router.get('/bookslenders/new', isAuthenticated, function(req, res){
    if (req.user.level === 1){
        res.render('bookslenders/new', {
            title: 'Create',
            req: req,
            errors: req.flash('errors'),
            inputs: req.flash('inputs')
        });
    } else {
        res.render('403');
    }
});

router.post('/bookslenders', isAuthenticated, function(req, res, next) {
        if (req.user.level === 1){
            return next();
        } else {
            res.render('403');
        }
    },[
        body('date_returned', 'Empty date returned.').not().isEmpty(),
        body('due_date', 'Empty due date.').not().isEmpty(),
        body('fine', 'Empty fine.').not().isEmpty(),
        body('book_id', 'Empty book id.').not().isEmpty(),
        body('lender_id', 'Empty lender id.').not().isEmpty()
    ]
    , (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            req.flash('errors', errors.array());
            req.flash('inputs', {date_returned: req.body.date_returned, due_date: req.body.due_date, fine: req.body.fine,
                book_id: req.body.book_id, lender_id: req.body.lender_id
            });
            res.redirect('/bookslenders/new');
        }
        else {
            sanitizeBody('date_returned').trim().escape();
            sanitizeBody('due_date').trim().escape();
            sanitizeBody('fine').trim().escape();
            sanitizeBody('book_id').trim().escape();
            sanitizeBody('lender_id').trim().escape();
            const date_returned = req.body.date_returned;
            const due_date = req.body.due_date;
            const fine = req.body.fine;
            const book_id = req.body.book_id;
            const lender_id = req.body.lender_id;
            connection.query('INSERT INTO bookslenders (date_returned, due_date, fine, book_id, lender_id) VALUES ' +
                '(?, ?, ?,?, ?)', [date_returned, due_date, fine, book_id, lender_id], function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Booklender created.');
                res.redirect('/bookslenders');
            });
        }
    }
);

router.get('/bookslenders/:id/edit', isResource, isAuthenticated, function(req, res) {
    if (req.user.level === 1){
        connection.query('SELECT id, date_returned, due_date, fine, book_id, lender_id FROM bookslenders WHERE id = ?', [req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                res.render('bookslenders/edit', {
                    title: 'Edit booklender',
                    req: req,
                    results: results,
                    errors: req.flash('errors'),
                    inputs: req.flash('inputs')
                });
            });
    } else {
        res.render('403');
    }

});

router.put('/bookslenders/:id', isResource, isAuthenticated, function(req, res, next) {
    if (req.user.level === 1){
        return next();
    } else {
        res.render('403');
    }
}, [
    body('date_returned', 'Empty date returned.').not().isEmpty(),
    body('due_date', 'Empty due date.').not().isEmpty(),
    body('fine', 'Empty fine.').not().isEmpty(),
    body('book_id', 'Empty book id.').not().isEmpty(),
    body('lender_id', 'Empty lender id.').not().isEmpty()
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        // There are errors. Render form again with sanitized values/errors messages.
        // Error messages can be returned in an array using `errors.array()`.
        req.flash('errors', errors.array());
        req.flash('inputs', {date_returned: req.body.date_returned, due_date: req.body.due_date, fine: req.body.fine,
            book_id: req.body.book_id, lender_id: req.body.lender_id});
        res.redirect(req._parsedOriginalUrl.pathname + '/edit');
    }
    else {
        sanitizeBody('date_returned').trim().escape();
        sanitizeBody('due_date').trim().escape();
        sanitizeBody('fine').trim().escape();
        sanitizeBody('book_id').trim().escape();
        sanitizeBody('lender_id').trim().escape();
        const date_returned = req.body.date_returned;
        const due_date = req.body.due_date;
        const fine = req.body.fine;
        const book_id = req.body.book_id;
        const lender_id = req.body.lender_id;
        connection.query('UPDATE bookslenders SET date_returned = ?, due_date = ?, fine = ?, book_id = ?, lender_id = ? WHERE id = ?',
            [date_returned, due_date, fine, book_id, lender_id, req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Booklender edited.');
                res.redirect('/bookslenders');
            });
    }
});

router.delete('/bookslenders/:id', isResource, isAuthenticated, function(req, res, next) {
    if (req.user.level === 1){
        connection.query('DELETE FROM bookslenders WHERE id = ?', [req.params.id], function (error, results, fields) {
            // error will be an Error if one occurred during the query
            // results will contain the results of the query
            // fields will contain information about the returned results fields (if any)
            if (error) {
                throw error;
            }
            req.flash('alert', 'Booklender deleted.');
            res.redirect('/bookslenders');
        });
    } else {
        res.render('403');
    }
});

// category routes
router.get('/categories', function(req, res, next) {
    if (req.isAuthenticated()) {
        connection.query('SELECT * FROM categories ORDER BY date_created DESC; SELECT count(*) as count FROM categories',
            function (error, results, fields) {
                if (error) {
                    throw error;
                }
                res.render('categories/index', {
                    title: 'Categories',
                    req: req,
                    results: results,
                    alert: req.flash('alert')
                });
            }
        );
    } else {
        res.redirect('/login');
    }
});

router.get('/categories/new', isAuthenticated, function(req, res){
    if (req.user.level === 1){
        res.render('categories/new', {
            title: 'Create',
            req: req,
            errors: req.flash('errors'),
            inputs: req.flash('inputs')
        });
    } else {
        res.render('403');
    }
});

router.post('/categories', isAuthenticated, function(req, res, next) {
        if (req.user.level === 1){
            return next();
        } else {
            res.render('403');
        }
    },[
        body('name', 'Empty name.').not().isEmpty(),
        body('description', 'Empty description.').not().isEmpty(),
    ]
    , (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            req.flash('errors', errors.array());
            req.flash('inputs', {name: req.body.name, description: req.body.description
            });
            res.redirect('/categories/new');
        }
        else {
            sanitizeBody('name').trim().escape();
            sanitizeBody('description').trim().escape();
            const name = req.body.name;
            const description = req.body.description;
            connection.query('INSERT INTO categories (name, description) VALUES ' +
                '(?, ?)', [name, description], function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Category created.');
                res.redirect('/categories');
            });
        }
    }
);

router.get('/categories/:id/edit', isResource, isAuthenticated, function(req, res) {
    if (req.user.level === 1){
        connection.query('SELECT id, name, description FROM categories WHERE id = ?', [req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                res.render('categories/edit', {
                    title: 'Edit category',
                    req: req,
                    results: results,
                    errors: req.flash('errors'),
                    inputs: req.flash('inputs')
                });
            });
    } else {
        res.render('403');
    }

});

router.put('/categories/:id', isResource, isAuthenticated, function(req, res, next) {
    if (req.user.level === 1){
        return next();
    } else {
        res.render('403');
    }
}, [
    body('name', 'Empty name.').not().isEmpty(),
    body('description', 'Empty description.').not().isEmpty(),
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        // There are errors. Render form again with sanitized values/errors messages.
        // Error messages can be returned in an array using `errors.array()`.
        req.flash('errors', errors.array());
        req.flash('inputs', {name: req.body.name, description: req.body.description});
        res.redirect(req._parsedOriginalUrl.pathname + '/edit');
    }
    else {
        sanitizeBody('name').trim().escape();
        sanitizeBody('description').trim().escape();
        const name = req.body.name;
        const description = req.body.description;
        connection.query('UPDATE categories SET name = ?, description = ? WHERE id = ?',
            [name, description, req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Category edited.');
                res.redirect('/categories');
            });
    }
});

router.delete('/categories/:id', isResource, isAuthenticated, function(req, res, next) {
    if (req.user.level === 1){
        connection.query('DELETE FROM categories WHERE id = ?', [req.params.id], function (error, results, fields) {
            // error will be an Error if one occurred during the query
            // results will contain the results of the query
            // fields will contain information about the returned results fields (if any)
            if (error) {
                throw error;
            }
            req.flash('alert', 'Category deleted.');
            res.redirect('/categories');
        });
    } else {
        res.render('403');
    }
});

// gender routes
router.get('/genders', function(req, res, next) {
    if (req.isAuthenticated()) {
        connection.query('SELECT * FROM genders ORDER BY date_created DESC; SELECT count(*) as count FROM genders',
            function (error, results, fields) {
                if (error) {
                    throw error;
                }
                res.render('genders/index', {
                    title: 'Genders',
                    req: req,
                    results: results,
                    alert: req.flash('alert')
                });
            }
        );
    } else {
        res.redirect('/login');
    }
});

router.get('/genders/new', isAuthenticated, function(req, res){
    if (req.user.level === 1){
        res.render('genders/new', {
            title: 'Create',
            req: req,
            errors: req.flash('errors'),
            inputs: req.flash('inputs')
        });
    } else {
        res.render('403');
    }
});

router.post('/genders', isAuthenticated, function(req, res, next) {
        if (req.user.level === 1){
            return next();
        } else {
            res.render('403');
        }
    },[
        body('gender', 'Empty gender.').not().isEmpty(),
    ]
    , (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            req.flash('errors', errors.array());
            req.flash('inputs', {gender: req.body.gender});
            res.redirect('/genders/new');
        }
        else {
            sanitizeBody('gender').trim().escape();
            const gender = req.body.gender;
            connection.query('INSERT INTO genders (gender) VALUES ' +
                '(?)', [gender], function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Gender created.');
                res.redirect('/genders');
            });
        }
    }
);

router.get('/genders/:id/edit', isResource, isAuthenticated, function(req, res) {
    if (req.user.level === 1){
        connection.query('SELECT id, gender FROM genders WHERE id = ?', [req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                res.render('genders/edit', {
                    title: 'Edit gender',
                    req: req,
                    results: results,
                    errors: req.flash('errors'),
                    inputs: req.flash('inputs')
                });
            });
    } else {
        res.render('403');
    }
});

router.put('/genders/:id', isResource, isAuthenticated, function(req, res, next) {
    if (req.user.level === 1){
        return next();
    } else {
        res.render('403');
    }
}, [
    body('gender', 'Empty gender.').not().isEmpty(),
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        // There are errors. Render form again with sanitized values/errors messages.
        // Error messages can be returned in an array using `errors.array()`.
        req.flash('errors', errors.array());
        req.flash('inputs', {gender: req.body.gender});
        res.redirect(req._parsedOriginalUrl.pathname + '/edit');
    }
    else {
        sanitizeBody('gender').trim().escape();
        const gender = req.body.gender;
        connection.query('UPDATE genders SET gender = ? WHERE id = ?',
            [gender, req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Gender edited.');
                res.redirect('/genders');
            });
    }
});

router.delete('/genders/:id', isResource, isAuthenticated, function(req, res, next) {
    if (req.user.level === 1){
        connection.query('DELETE FROM genders WHERE id = ?', [req.params.id], function (error, results, fields) {
            // error will be an Error if one occurred during the query
            // results will contain the results of the query
            // fields will contain information about the returned results fields (if any)
            if (error) {
                throw error;
            }
            req.flash('alert', 'Gender deleted.');
            res.redirect('/genders');
        });
    } else {
        res.render('403');
    }
});

// lender routes
router.get('/lenders', function(req, res, next) {
    if (req.isAuthenticated()) {
        connection.query('SELECT * FROM lenders ORDER BY date_created DESC; SELECT count(*) as count FROM lenders',
            function (error, results, fields) {
                if (error) {
                    throw error;
                }
                res.render('lenders/index', {
                    title: 'Lenders',
                    req: req,
                    results: results,
                    alert: req.flash('alert')
                });
            }
        );
    } else {
        res.redirect('/login');
    }
});

router.get('/lenders/new', isAuthenticated, function(req, res){
    if (req.user.level === 1){
        res.render('lenders/new', {
            title: 'Create',
            req: req,
            errors: req.flash('errors'),
            inputs: req.flash('inputs')
        });
    } else {
        res.render('403');
    }
});

router.post('/lenders', isAuthenticated, function(req, res, next) {
        if (req.user.level === 1){
            return next();
        } else {
            res.render('403');
        }
    },[
        body('first_name', 'Empty first name.').not().isEmpty(),
        body('last_name', 'Empty last name.').not().isEmpty(),
        body('age', 'Empty age.').not().isEmpty(),
        body('dob', 'Empty dob.').not().isEmpty(),
        body('email', 'Empty email.').not().isEmpty(),
        body('phone_number', 'Empty phone number.').not().isEmpty(),
        body('gender_id', 'Empty gender id.').not().isEmpty(),
        body('address_id', 'Empty address id.').not().isEmpty(),
        body('first_name', 'First Name must be between 5-100 characters.').isLength({min:5, max:100}),
        body('last_name', 'Last Name must be between 5-100 characters.').isLength({min:5, max:100}),
        body('email', 'Email must be between 5-200 characters.').isLength({min:5, max:200})
    ]
    , (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            req.flash('errors', errors.array());
            req.flash('inputs', {first_name: req.body.first_name, last_name: req.body.last_name, age: req.body.age,
                dob: req.body.dob, email: req.body.email, phone_number: req.body.phone_number,
                gender_id: req.body.gender_id, address_id: req.body.address_id});
            res.redirect('/lenders/new');
        }
        else {
            sanitizeBody('first_name').trim().escape();
            sanitizeBody('last_name').trim().escape();
            sanitizeBody('age').trim().escape();
            sanitizeBody('dob').trim().escape();
            sanitizeBody('email').trim().escape();
            sanitizeBody('phone_number').trim().escape();
            sanitizeBody('gender_id').trim().escape();
            sanitizeBody('address_id').trim().escape();
            const first_name = req.body.first_name;
            const last_name = req.body.last_name;
            const age = req.body.age;
            const dob = req.body.dob;
            const email = req.body.email;
            const phone_number = req.body.phone_number;
            const gender_id = req.body.gender_id;
            const address_id = req.body.address_id;
            connection.query('INSERT INTO lenders (first_name, last_name, age, dob, email, phone_number, gender_id, address_id) VALUES ' +
                '(?, ?, ?,?, ?, ?,?, ?)', [first_name, last_name, age, dob, email, phone_number, gender_id, address_id], function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Lender created.');
                res.redirect('/lenders');
            });
        }
    }
);

router.get('/lenders/:id/edit', isResource, isAuthenticated, function(req, res) {
    if (req.user.level === 1){
        connection.query('SELECT id, first_name, last_name, age, dob, email, phone_number, gender_id, address_id FROM lenders WHERE id = ?', [req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                res.render('lenders/edit', {
                    title: 'Edit lender',
                    req: req,
                    results: results,
                    errors: req.flash('errors'),
                    inputs: req.flash('inputs')
                });
            });
    } else {
        res.render('403');
    }

});

router.put('/lenders/:id', isResource, isAuthenticated, function(req, res, next) {
    if (req.user.level === 1){
        return next();
    } else {
        res.render('403');
    }
}, [
    body('first_name', 'Empty first name.').not().isEmpty(),
    body('last_name', 'Empty last name.').not().isEmpty(),
    body('age', 'Empty age.').not().isEmpty(),
    body('dob', 'Empty dob.').not().isEmpty(),
    body('email', 'Empty email.').not().isEmpty(),
    body('phone_number', 'Empty phone number.').not().isEmpty(),
    body('gender_id', 'Empty gender id.').not().isEmpty(),
    body('address_id', 'Empty address id.').not().isEmpty(),
    body('first_name', 'First Name must be between 5-100 characters.').isLength({min:5, max:100}),
    body('last_name', 'Last Name must be between 5-100 characters.').isLength({min:5, max:100}),
    body('email', 'Email must be between 5-200 characters.').isLength({min:5, max:200})
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        // There are errors. Render form again with sanitized values/errors messages.
        // Error messages can be returned in an array using `errors.array()`.
        req.flash('errors', errors.array());
        req.flash('inputs', {first_name: req.body.first_name, last_name: req.body.last_name, age: req.body.age,
            dob: req.body.dob, email: req.body.email, phone_number: req.body.phone_number,
            gender_id: req.body.gender_id, address_id: req.body.address_id});
        res.redirect(req._parsedOriginalUrl.pathname + '/edit');
    }
    else {
        sanitizeBody('first_name').trim().escape();
        sanitizeBody('last_name').trim().escape();
        sanitizeBody('age').trim().escape();
        sanitizeBody('dob').trim().escape();
        sanitizeBody('email').trim().escape();
        sanitizeBody('phone_number').trim().escape();
        sanitizeBody('gender_id').trim().escape();
        sanitizeBody('address_id').trim().escape();
        const first_name = req.body.first_name;
        const last_name = req.body.last_name;
        const age = req.body.age;
        const dob = req.body.dob;
        const email = req.body.email;
        const phone_number = req.body.phone_number;
        const gender_id = req.body.gender_id;
        const address_id = req.body.address_id;
        connection.query('UPDATE lenders SET first_name = ?, last_name = ?, age = ?, dob = ?,' +
            'email = ?, phone_number = ?, gender_id = ?, address_id = ? WHERE id = ?',
            [first_name, last_name, age, dob, email, phone_number, gender_id, address_id, req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Lender edited.');
                res.redirect('/lenders');
            });
    }
});

router.delete('/lenders/:id', isResource, isAuthenticated, function(req, res, next) {
    if (req.user.level === 1){
        connection.query('DELETE FROM lenders WHERE id = ?', [req.params.id], function (error, results, fields) {
            // error will be an Error if one occurred during the query
            // results will contain the results of the query
            // fields will contain information about the returned results fields (if any)
            if (error) {
                throw error;
            }
            req.flash('alert', 'Lender deleted.');
            res.redirect('/lenders');
        });
    } else {
        res.render('403');
    }
});

// publisher routes
router.get('/publishers', function(req, res, next) {
    if (req.isAuthenticated()) {
        connection.query('SELECT * FROM publishers; SELECT count(*) as count FROM publishers',
            function (error, results, fields) {
                if (error) {
                    throw error;
                }
                res.render('publishers/index', {
                    title: 'Publishers',
                    req: req,
                    results: results,
                    alert: req.flash('alert')
                });
            }
        );
    } else {
        res.redirect('/login');
    }
});

router.get('/publishers/new', isAuthenticated, function(req, res){
    if (req.user.level === 1){
        res.render('publishers/new', {
            title: 'Create',
            req: req,
            errors: req.flash('errors'),
            inputs: req.flash('inputs')
        });
    } else {
        res.render('403');
    }
});

router.post('/publishers', isAuthenticated, function(req, res, next) {
        if (req.user.level === 1){
            return next();
        } else {
            res.render('403');
        }
    },[
        body('name', 'Empty name.').not().isEmpty()
    ]
    , (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            req.flash('errors', errors.array());
            req.flash('inputs', {name: req.body.name});
            res.redirect('/publishers/new');
        }
        else {
            sanitizeBody('name').trim().escape();
            const name = req.body.name;
            connection.query('INSERT INTO publishers (name) VALUES ' +
                '(?)', [name], function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Publisher created.');
                res.redirect('/publishers');
            });
        }
    }
);

router.get('/publishers/:id/edit', isResource, isAuthenticated, function(req, res) {
    if (req.user.level === 1){
        connection.query('SELECT id, name FROM publishers WHERE id = ?', [req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                res.render('publishers/edit', {
                    title: 'Edit publisher',
                    req: req,
                    results: results,
                    errors: req.flash('errors'),
                    inputs: req.flash('inputs')
                });
            });
    } else {
        res.render('403');
    }

});

router.put('/publishers/:id', isResource, isAuthenticated, function(req, res, next) {
    if (req.user.level === 1){
        return next();
    } else {
        res.render('403');
    }
}, [
    body('name', 'Empty name.').not().isEmpty()
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        // There are errors. Render form again with sanitized values/errors messages.
        // Error messages can be returned in an array using `errors.array()`.
        req.flash('errors', errors.array());
        req.flash('inputs', {name: req.body.name});
        res.redirect(req._parsedOriginalUrl.pathname + '/edit');
    }
    else {
        sanitizeBody('name').trim().escape();
        const name = req.body.name;
        connection.query('UPDATE publishers SET name = ? WHERE id = ?',
            [name, req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Publisher edited.');
                res.redirect('/publishers');
            });
    }
});

router.delete('/publishers/:id', isResource, isAuthenticated, function(req, res, next) {
    if (req.user.level === 1){
        connection.query('DELETE FROM publishers WHERE id = ?', [req.params.id], function (error, results, fields) {
            // error will be an Error if one occurred during the query
            // results will contain the results of the query
            // fields will contain information about the returned results fields (if any)
            if (error) {
                throw error;
            }
            req.flash('alert', 'Publisher deleted.');
            res.redirect('/publishers');
        });
    } else {
        res.render('403');
    }
});

// staff routes
router.get('/staffs', function(req, res, next) {
    if (req.isAuthenticated()) {
        connection.query('SELECT * FROM staffs ORDER BY date_created DESC; SELECT count(*) as count FROM staffs',
            function (error, results, fields) {
                if (error) {
                    throw error;
                }
                res.render('staffs/index', {
                    title: 'Staffs',
                    req: req,
                    results: results,
                    alert: req.flash('alert')
                });
            }
        );
    } else {
        res.redirect('/login');
    }
});

router.get('/staffs/new', isAuthenticated, function(req, res){
    if (req.user.level === 1){
        res.render('staffs/new', {
            title: 'Create',
            req: req,
            errors: req.flash('errors'),
            inputs: req.flash('inputs')
        });
    } else {
        res.render('403');
    }
});

router.post('/staffs', isAuthenticated, function(req, res, next) {
        if (req.user.level === 1){
            return next();
        } else {
            res.render('403');
        }
    },[
        body('first_name', 'Empty first name.').not().isEmpty(),
        body('last_name', 'Empty last name.').not().isEmpty(),
        body('age', 'Empty age.').not().isEmpty(),
        body('dob', 'Empty dob.').not().isEmpty(),
        body('email', 'Empty email.').not().isEmpty(),
        body('phone_number', 'Empty phone number.').not().isEmpty(),
        body('gender_id', 'Empty gender id.').not().isEmpty(),
        body('address_id', 'Empty address id.').not().isEmpty(),
        body('first_name', 'First Name must be between 5-100 characters.').isLength({min:5, max:100}),
        body('last_name', 'Last Name must be between 5-100 characters.').isLength({min:5, max:100}),
        body('email', 'Email must be between 5-200 characters.').isLength({min:5, max:200})
    ]
    , (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            req.flash('errors', errors.array());
            req.flash('inputs', {first_name: req.body.first_name, last_name: req.body.last_name, age: req.body.age,
                dob: req.body.dob, email: req.body.email, phone_number: req.body.phone_number,
                gender_id: req.body.gender_id, address_id: req.body.address_id});
            res.redirect('/staffs/new');
        }
        else {
            sanitizeBody('first_name').trim().escape();
            sanitizeBody('last_name').trim().escape();
            sanitizeBody('age').trim().escape();
            sanitizeBody('dob').trim().escape();
            sanitizeBody('email').trim().escape();
            sanitizeBody('phone_number').trim().escape();
            sanitizeBody('gender_id').trim().escape();
            sanitizeBody('address_id').trim().escape();
            const first_name = req.body.first_name;
            const last_name = req.body.last_name;
            const age = req.body.age;
            const dob = req.body.dob;
            const email = req.body.email;
            const phone_number = req.body.phone_number;
            const gender_id = req.body.gender_id;
            const address_id = req.body.address_id;
            connection.query('INSERT INTO staffs (first_name, last_name, age, dob, email, phone_number, gender_id, address_id) VALUES ' +
                '(?, ?, ?,?, ?, ?,?, ?)', [first_name, last_name, age, dob, email, phone_number, gender_id, address_id], function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Staff created.');
                res.redirect('/staffs');
            });
        }
    }
);

router.get('/staffs/:id/edit', isResource, isAuthenticated, function(req, res) {
    if (req.user.level === 1){
        connection.query('SELECT id, first_name, last_name, age, dob, email, phone_number, gender_id, address_id FROM staffs WHERE id = ?', [req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                res.render('staffs/edit', {
                    title: 'Edit staff',
                    req: req,
                    results: results,
                    errors: req.flash('errors'),
                    inputs: req.flash('inputs')
                });
            });
    } else {
        res.render('403');
    }

});

router.put('/staffs/:id', isResource, isAuthenticated, function(req, res, next) {
    if (req.user.level === 1){
        return next();
    } else {
        res.render('403');
    }
}, [
    body('first_name', 'Empty first name.').not().isEmpty(),
    body('last_name', 'Empty last name.').not().isEmpty(),
    body('age', 'Empty age.').not().isEmpty(),
    body('dob', 'Empty dob.').not().isEmpty(),
    body('email', 'Empty email.').not().isEmpty(),
    body('phone_number', 'Empty phone number.').not().isEmpty(),
    body('gender_id', 'Empty gender id.').not().isEmpty(),
    body('address_id', 'Empty address id.').not().isEmpty(),
    body('first_name', 'First Name must be between 5-100 characters.').isLength({min:5, max:100}),
    body('last_name', 'Last Name must be between 5-100 characters.').isLength({min:5, max:100}),
    body('email', 'Email must be between 5-200 characters.').isLength({min:5, max:200})
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        // There are errors. Render form again with sanitized values/errors messages.
        // Error messages can be returned in an array using `errors.array()`.
        req.flash('errors', errors.array());
        req.flash('inputs', {first_name: req.body.first_name, last_name: req.body.last_name, age: req.body.age,
            dob: req.body.dob, email: req.body.email, phone_number: req.body.phone_number,
            gender_id: req.body.gender_id, address_id: req.body.address_id});
        res.redirect(req._parsedOriginalUrl.pathname + '/edit');
    }
    else {
        sanitizeBody('first_name').trim().escape();
        sanitizeBody('last_name').trim().escape();
        sanitizeBody('age').trim().escape();
        sanitizeBody('dob').trim().escape();
        sanitizeBody('email').trim().escape();
        sanitizeBody('phone_number').trim().escape();
        sanitizeBody('gender_id').trim().escape();
        sanitizeBody('address_id').trim().escape();
        const first_name = req.body.first_name;
        const last_name = req.body.last_name;
        const age = req.body.age;
        const dob = req.body.dob;
        const email = req.body.email;
        const phone_number = req.body.phone_number;
        const gender_id = req.body.gender_id;
        const address_id = req.body.address_id;
        connection.query('UPDATE staffs SET first_name = ?, last_name = ?, age = ?, dob = ?,' +
            'email = ?, phone_number = ?, gender_id = ?, address_id = ? WHERE id = ?',
            [first_name, last_name, age, dob, email, phone_number, gender_id, address_id, req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Staff edited.');
                res.redirect('/staffs');
            });
    }
});

router.delete('/staffs/:id', isResource, isAuthenticated, function(req, res, next) {
    if (req.user.level === 1){
        connection.query('DELETE FROM staffs WHERE id = ?', [req.params.id], function (error, results, fields) {
            // error will be an Error if one occurred during the query
            // results will contain the results of the query
            // fields will contain information about the returned results fields (if any)
            if (error) {
                throw error;
            }
            req.flash('alert', 'Staff deleted.');
            res.redirect('/staffs');
        });
    } else {
        res.render('403');
    }
});

router.get('/login', isNotAuthenticated, function(req, res, next){
    res.render('login', {
        title: 'Log in',
        req: req,
        errors: req.flash('errors'),
        input: req.flash('input'),
        alert: req.flash('alert')
    });
});

router.post('/login', isNotAuthenticated, passport.authenticate('local', {
        successRedirect: '/',
        failureRedirect: '/login',
        failureFlash: true
    })
);

router.get('/logout', isAuthenticated, function(req, res){
    req.logout();
    res.redirect('/login');
});

module.exports = router;
