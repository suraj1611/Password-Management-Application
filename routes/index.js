var express = require('express');
var router = express.Router();
var userModule = require('../modules/user');
var passCatModel = require('../modules/password_category');
var passModel = require('../modules/add_password');
var bcrypt = require('bcryptjs');
var jwt = require('jsonwebtoken');
const { check, validationResult } = require('express-validator');
var getPassCat = passCatModel.find({});
var getAllPass = passModel.find({});

if (typeof localStorage === "undefined" || localStorage === null) {
  var LocalStorage = require('node-localstorage').LocalStorage;
  localStorage = new LocalStorage('./scratch');
}

function checkLoginUser(req,res,next){
  var userToken = localStorage.getItem('userToken');
  try {
    var decoded = jwt.verify(userToken, 'loginToken');
  } catch(err) {
    res.redirect('/');
  }
  next();
}

function checkEmail(req,res,next){
    var email = req.body.email;
    var checkEmailExist = userModule.findOne({email:email});
    checkEmailExist.exec((err,data)=>{
        if(err)
        throw err;
        if(data)
        {
          return res.render('signup', { title: 'Password Management System', msg:'Email already exists'});
        }
        next();
    });
    
}

function checkUsername(req,res,next){
  var username = req.body.uname;
  var checkUserExist = userModule.findOne({username:username});
  checkUserExist.exec((err,data)=>{
      if(err)
      throw err;
      if(data)
      {
      return res.render('signup', { title: 'Password Management System', msg:'Username already exists'});
      }
      next();
    });
 
}

/* GET home page. */
router.get('/', function(req, res, next) {
  var loginUser = localStorage.getItem('loginUser');
  if(loginUser){
    res.redirect('./dashboard');
  }else{
  res.render('index', { title: 'Password Management System', msg:'' });
  }
});

router.post('/', function(req, res, next) {

  var username = req.body.uname;
  var password = req.body.password;
  var checkUser = userModule.findOne({username:username});
  checkUser.exec((err,data)=>{
    if(err)
    throw err;

    var getUserID = data._id;
    var getPassword = data.password;
    if(bcrypt.compareSync(password,getPassword)){
      var token = jwt.sign({userID: getUserID}, 'loginToken');
      localStorage.setItem('userToken', token);
      localStorage.setItem('loginUser', username);
      res.redirect('/dashboard');
    }
    else{
      res.render('index', { title: 'Password Management System', msg:'Invalid Username and password' });
    }
  })
});

router.get('/dashboard', checkLoginUser, function(req, res, next) {
  var loginUser = localStorage.getItem('loginUser');
  console.log(loginUser);
  res.render('dashboard', { title: 'Password Management System', loginUser:loginUser, msg:''});
});

router.get('/signup', function(req, res, next) {
  var loginUser = localStorage.getItem('loginUser');
  if(loginUser){
    res.redirect('./dashboard');
  }else{
  res.render('signup', { title: 'Password Management System', msg:''});
  }
});

router.post('/signup',checkUsername,checkEmail, function(req, res, next) {

  var username = req.body.uname;
  var email = req.body.email;
  var password = req.body.password;
  var cnfpassword = req.body.cnfpassword;

  if(password!=cnfpassword){
    res.render('signup', { title: 'Password Management System',msg:'Passwords do not match!'});

  }
  else{
    password = bcrypt.hashSync(req.body.password,10);
  var userDetails = new userModule({
    username:username,
    email:email,
    password:password
  });

  userDetails.save((err,doc)=>{
      if(err)
        throw err;
      
      res.render('signup', { title: 'Password Management System',msg:'User Regitered Successfully'});
  })
  }

});


router.get('/password-category',checkLoginUser, function(req, res, next) {
  var loginUser = localStorage.getItem('loginUser');
  getPassCat.exec((err,data)=>{
    if(err)
    throw err;
    res.render('password_category', { title: 'Password Management System', loginUser:loginUser, records:data  });
  });
});

router.get('/password-category/delete/:id',checkLoginUser, function(req, res, next) {
  var loginUser = localStorage.getItem('loginUser');
  var passCatId = req.params.id;
  var passDelete = passCatModel.findByIdAndDelete(passCatId);
  passDelete.exec((err)=>{
    if(err)
    throw err;
    res.redirect('/password-category')
  });
});

router.get('/password-category/edit/:id',checkLoginUser, function(req, res, next) {
  var loginUser = localStorage.getItem('loginUser');
  var passCatId = req.params.id;
  //console.log(passCatId);
  var getpassCategory = passCatModel.findById(passCatId);
  getpassCategory.exec((err,data)=>{
    if(err)
    throw err;
    res.render('edit_PassCat', { title: 'Password Management System', loginUser:loginUser, records:data, errors:'', success:'' , id:passCatId });
  });
});

router.post('/password-category/edit',checkLoginUser, function(req, res, next) {
  var loginUser = localStorage.getItem('loginUser');
  var passCatId = req.body.id;
  var passwordCategory = req.body.passwordCategory;
  var updatePassCat = passCatModel.findByIdAndUpdate(passCatId,{password_category:passwordCategory});
  updatePassCat.exec((err,doc)=>{
    if(err)
    throw err;
    res.redirect('/password-category');
  });
});

router.get('/add-new-category',checkLoginUser, function(req, res, next) {
  var loginUser = localStorage.getItem('loginUser');
  res.render('addNewCategory', { title: 'Password Management System', loginUser:loginUser, errors:'', success:''});
});

router.post('/add-new-category',checkLoginUser, [ check('passwordCategory','Cannot be blank').isLength({ min: 1 })],function(req, res, next) {
  var loginUser = localStorage.getItem('loginUser');
  const errors = validationResult(req);
  if(!errors.isEmpty()){
    res.render('addNewCategory', { title: 'Password Management System', loginUser:loginUser, errors:errors.mapped(), success:'' });
  }
  else{

    var passCatName = req.body.passwordCategory;
    var passCatDetails = new passCatModel ({
      password_category : passCatName
    });

    passCatDetails.save((err,doc)=>{
      if(err)
      throw err;
      res.render('addNewCategory', { title: 'Password Management System', loginUser:loginUser, errors:'', success:'Password Category added Successfully' });

    })


  }
});

router.get('/add-new-password',checkLoginUser, function(req, res, next) {
  var loginUser = localStorage.getItem('loginUser');
  getPassCat.exec((err,data)=>{
    if(err)
    throw err;
    res.render('add-new-password', { title: 'Password Management System', loginUser:loginUser, records:data, success:'' });

  });
});

router.post('/add-new-password',checkLoginUser, function(req, res, next) {
  var loginUser = localStorage.getItem('loginUser');
  var pass_cat = req.body.pass_cat;
  var pass_details = req.body.pass_details;

  var password_details = new passModel({
    password_category:pass_cat,
    password_details:pass_details
  });

  password_details.save((err,doc)=>{
    getPassCat.exec((err,data)=>{
      if(err)
      throw err;
    res.render('add-new-password', { title: 'Password Management System', loginUser:loginUser, records:data, success:'Password details added Successfully'});
  });
  
  });
});

router.get('/view-all-password',checkLoginUser, function(req, res, next) {
  var loginUser = localStorage.getItem('loginUser');
  getAllPass.exec((err,data)=>{
    if(err)
    throw err;
    res.render('view-all-password', { title: 'Password Management System', loginUser:loginUser, records:data });
  });
});

router.get('/password_details',checkLoginUser, function(req, res, next) {
    res.redirect('/dashboard');
});

router.get('/password_details/edit/:id',checkLoginUser, function(req, res, next) {
  var loginUser = localStorage.getItem('loginUser');
  var id = req.params.id;
  var getPassDetails = passModel.findById({_id:id});
  getPassDetails.exec((err,data)=>{
    getPassCat.exec((err,data1)=>{
    if(err)
    throw err;
    res.render('edit_password_details', { title: 'Password Management System', loginUser:loginUser, records:data1, record:data, success:'' });
  });
}); 
});

router.post('/password_details/edit/:id',checkLoginUser, function(req, res, next) {
  var loginUser = localStorage.getItem('loginUser');
  var id = req.params.id;
  var pass_cat = req.body.pass_cat;
  var pass_details = req.body.pass_details; 
  passModel.findByIdAndUpdate(id,{password_category : pass_cat, password_details :pass_details}).exec(function(err){
  if(err) throw err;

  var getPassDetails = passModel.findById({_id:id});
  getPassDetails.exec((err,data)=>{
    getPassCat.exec((err,data1)=>{
    if(err)
    throw err;
    res.render('edit_password_details', { title: 'Password Management System', loginUser:loginUser, records:data1, record:data, success:'Password details updated successfully' });
  });
});
}); 
});

router.get('/password_details/delete/:id',checkLoginUser, function(req, res, next) {
  var loginUser = localStorage.getItem('loginUser');
  var id = req.params.id;
  var passDelete = passModel.findByIdAndDelete(id);
  passDelete.exec((err)=>{
    if(err)
    throw err;
    res.redirect('/view-all-password')
  });
});

router.get('/logout', function(req, res, next) {
  localStorage.removeItem('userToken');
  localStorage.removeItem('loginUser');
  res.redirect('/');
});


module.exports = router;
