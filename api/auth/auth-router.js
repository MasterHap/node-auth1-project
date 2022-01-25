// Require `checkUsernameFree`, `checkUsernameExists` and `checkPasswordLength`
// middleware functions from `auth-middleware.js`. You will need them here!
const router = require('express').Router()
const { add, findBy } = require('../users/users-model')
const bcrypt = require('bcryptjs')

const validatePayload = (req, res, next) => { next() }

router.post('/register', validatePayload, async (req, res, next) => {
  try {
    const { username, password } = req.body
    const hash = bcrypt.hashSync(password, 8)
    const user = { username, password: hash }
    const createdUser = await add(user)
    res.status(201).json(createdUser)
  } catch (err) {
    next(err)
  }
})

router.post('/login', validatePayload, async (req, res, next) => {
try {
  const { username, password } = req.body
  const [user] = await findBy({ username })

  if (user && bcrypt.compareSync(password, user.password)) {
    console.log(user)
  }else {
    next({ status: 401, message: 'bad credentials' })
  }

} catch (err) {
  next(err)
}
})

router.get('/logout', validatePayload, async (req, res, next) => {
  res.json('logout wired')
})

module.exports = router
/**
  1 [POST] /api/auth/register { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "user_id": 2,
    "username": "sue"
  }

  response on username taken:
  status 422
  {
    "message": "Username taken"
  }

  response on password three chars or less:
  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
 */


/**
  2 [POST] /api/auth/login { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "message": "Welcome sue!"
  }

  response on invalid credentials:
  status 401
  {
    "message": "Invalid credentials"
  }
 */


/**
  3 [GET] /api/auth/logout

  response for logged-in users:
  status 200
  {
    "message": "logged out"
  }

  response for not-logged-in users:
  status 200
  {
    "message": "no session"
  }
 */

 
// Don't forget to add the router to the `exports` object so it can be required in other modules
