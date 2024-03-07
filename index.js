require('dotenv').config();
const express = require('express');
const app = express();
const http = require('http');
const server = http.createServer(app);
const { Server } = require('socket.io');
const io = new Server(server);
const PORT = process.env.PORT || 3000;
const path = require('path');
const session = require('express-session');
const flash = require('express-flash');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

//
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

//
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(
  session({
    resave: false,
    saveUninitialized: false,
    secret: process.env.SESSION_SECRET,
  })
);
app.use(flash());

//
passport.use(
  new LocalStrategy(
    {
      passReqToCallback: true,
      usernameField: 'email',
    },
    async (req, email, password, done) => {
      try {
        if (!email) {
          // req.flash('email', { email: 'Invalid credentials.' });
          done(null, false, new Error('Invalid credentials'));
        }

        const user = await prisma.user.findUnique({
          where: {
            email: email,
          },
        });

        if (
          user?.email == email &&
          bcrypt.compareSync(password, user?.password)
        ) {
          done(null, user);
        } else {
          done(null, false, new Error('Invalid credentials'));
        }
      } catch (error) {
        done(error);
      }
    }
  )
);
app.use(passport.initialize());
app.use(passport.session());

const AUTHENTICATED = (req, res, next) => {
  if (req.isAuthenticated()) {
    next();
  } else {
    res.redirect('/sign_in');
  }
};

const UNAUTHENTICATED = (req, res, next) => {
  if (!req.isAuthenticated()) {
    next();
  } else {
    res.redirect('/');
  }
};

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  const user = await prisma.user.findUnique({
    where: {
      id: id,
    },
  });
  done(null, user);
});

//
io.on('connect', (socket) => {
  console.log('connected');

  socket.on('disconnected', () => {
    console.log('disconnected');
  });
});

// sign_in|sign_out|sign_up/index
app.get('/', AUTHENTICATED, (req, res) => {
  res.render('index', { user: req.user });
});

app.get('/sign_in', UNAUTHENTICATED, (req, res) => {
  console.log(req.flash('error'));
  res.render('sign_in');
});
app.post('/sign_in', [
  UNAUTHENTICATED,
  passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/sign_in',
    failureFlash: true,
  }),
]);

app.get('/sign_up', UNAUTHENTICATED, (req, res) => {
  res.render('sign_up');
});
app.post('/sign_up', UNAUTHENTICATED, async (req, res) => {
  try {
    const salt = await bcrypt.genSalt(10);
    const password = await bcrypt.hash(req.body.password, salt);

    // email taken

    const user = await prisma.user.create({
      data: {
        name: req.body.name,
        email: req.body.email,
        password: password,
      },
    });

    console.log(user);

    // req.logIn({ email: user.email, password: user.password }, (error) => {
    //   if (error) {
    //     return res.redirect('/sign_in');
    //   }
    //   // account
    //   return res.redirect('/');
    // });
    return res.redirect('/sign_in');
  } catch (error) {
    console.log(error);
    return res.render('sign_up');
  }
});

app.post('/sign_out', AUTHENTICATED, (req, res) => {
  req.logout((error) => {
    if (error) {
      return next(error);
    }
    res.render('sign_in');
  });
});

//
server.listen(PORT, () => {
  console.log(`http://127.0.0.1:${PORT}`);
});
