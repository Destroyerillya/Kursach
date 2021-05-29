using JwtTest.EF;
using JwtTest.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using JwtTest.Helpers;
using Microsoft.AspNetCore.Identity;
using Isopoh.Cryptography.Argon2;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Hosting;
using Microsoft.AspNetCore.Http;
using System.IO;
using System.Threading;
using Microsoft.AspNetCore.StaticFiles;
using Microsoft.EntityFrameworkCore;

namespace JwtTest.Controllers
{
    public class AccountController : BaseController
    {


        public AccountController(JwtContext context, IOptions<AuthOptions> options, IHostEnvironment hostEnvironment)
        {
            this.context = context;
            this.options = options;
            this.hostEnvironment = hostEnvironment;
        }

        [HttpPost("/token")]
        public IActionResult Token(string username, string password)
        {
            var identity = GetIdentity(username, password);
            if (identity == null)
            {
                return BadRequest(new { errorText = "Invalid username or password." });
            }

            var now = DateTime.UtcNow;
            // создаем JWT-токен
            var jwt = new JwtSecurityToken(
                    issuer: options.Value.Issuer,
                    audience: options.Value.Audience,
                    notBefore: now,
                    claims: identity.Claims,
                    expires: now.Add(TimeSpan.FromMinutes(options.Value.Lifetime)),
                    signingCredentials: new SigningCredentials(options.Value.GetSymmetricSecurityKey(), SecurityAlgorithms.HmacSha256));
            var encodedJwt = new JwtSecurityTokenHandler().WriteToken(jwt);
            var response = new
            {
                access_token = encodedJwt,
                username = identity.Name
            };
            return Json(response);
        }

        private ClaimsIdentity GetIdentity(string username, string password)
        {
            Person person = context.People.SingleOrDefault(x => x.Login == username);
            if (person != null && Argon2.Verify(person.PasswordHash, password))
            {
                var claims = new List<Claim>
                {
                    new Claim(ClaimsIdentity.DefaultNameClaimType, person.Login),
                    new Claim(ClaimsIdentity.DefaultRoleClaimType, Enum.GetName(person.Role))
                };
                ClaimsIdentity claimsIdentity =
                new ClaimsIdentity(claims, "Token", ClaimsIdentity.DefaultNameClaimType,
                    ClaimsIdentity.DefaultRoleClaimType);
                return claimsIdentity;
            }
            // если пользователя не найдено
            return null;
        }

        private async Task<bool> RegisterUser(string username, string password, UserRole role, IFormFile file)
        {
            if (context.People.Any(p => p.Login == username))
                return false;
            string randomFile = null;
            if (file != null)
            {
                randomFile = $"{Path.GetRandomFileName()}.{Path.GetExtension(file.FileName)}";

            }
            Person person = new Person()
            {
                Login = username,
                PasswordHash = Argon2.Hash(password),
                Role = role,
                Avatar = randomFile
            };
            await context.People.AddAsync(person);
            await context.SaveChangesAsync();
            if (file != null)
            {
                person = context.Entry(person).Entity;
                string userPath = Path.Combine(ImageFolder, person.Id.ToString());
                if (!Directory.Exists(userPath))
                    Directory.CreateDirectory(userPath);
                await file.WriteToFile(Path.Combine(userPath, randomFile));
            }
            return true;
        }

        [HttpGet]
        public IActionResult Register()
        {
            ClaimsIdentity cookieClaims = User.Identities.FirstOrDefault(cc => cc.AuthenticationType == "ApplicationCookie");
            bool authenticated = cookieClaims != null && cookieClaims.IsAuthenticated;
            if (!authenticated)
            {
                return View();
            }
            else
            {
                return Redirect("/Account/UserPage");
            }
        }

        [HttpPost]
        public async Task<IActionResult> Register(RegisterModel model)
        {
            if (!ModelState.IsValid)
                return View(model);
            if (await RegisterUser(model.Username, model.Password, UserRole.User, model.Avatar))
                return Redirect("/Home/Index");
            else
            {
                ModelState.AddModelError("Username", "Данное имя уже используется");
                return (View(model));
            }
        }

        [HttpGet]
        public IActionResult Login()
        {
            ClaimsIdentity cookieClaims = User.Identities.FirstOrDefault(cc => cc.AuthenticationType == "ApplicationCookie");
            bool authenticated = cookieClaims != null && cookieClaims.IsAuthenticated;
            if (!authenticated)
            {
                return View();
            }
            else
            {
                return Redirect("/Account/UserPage");
            }
        }

        [HttpPost]
        public async Task<IActionResult> Login(LoginModel model)
        {
            if (!ModelState.IsValid)
                return View(model);
            Person person = context.People.SingleOrDefault(usr => usr.Login == model.Username);
            if (person == null || !Argon2.Verify(person.PasswordHash, model.Password))
            {
                ModelState.AddModelError("Username", "Неверное имя пользователя или пароль");
                return View(model);
            }
            await Authenticate(person.Login, person.Role);
            return Redirect("/Account/UserPage");
        }

        [Authorize]
        public async Task<IActionResult> LogOff()
        {
            await Logout();
            return Redirect("/Home/Index");
        }

        [Authorize(Roles = "Admin")]
        public IActionResult CreateUser()
        {
            return View();
        }

        [HttpPost]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> CreateUser(UserModel model)
        {
            if (!ModelState.IsValid)
                return View(model);
            if (await RegisterUser(model.Username, model.Password, model.Role, model.Avatar))
                return Redirect("/Home/Index");
            else
            {
                ModelState.AddModelError("Username", "Данное имя уже используется");
                return (View(model));
            }
        }

        [Authorize(Roles = "Admin")]
        public IActionResult ListUsers()
        {
            return View(context.People);
        }

        [Authorize(Roles = "Admin")]
        public IActionResult EditUser(int id)
        {
            Person person = context.People.Find(id);
            return View(person.ToEditUserModel());
        }

        [HttpPost]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> EditUser(EditUserModel model)
        {
            if (!ModelState.IsValid)
                return View(model);
            Person person = context.People.Find(model.Id);
            if (person != null)
            {
                bool taken = person.Login != model.Username && context.People.Any(p => p.Login == model.Username);
                if (taken)
                {
                    ModelState.AddModelError("Username", "Данное имя уже занято");
                    return (View(model));
                }
                if (model.Avatar != null)
                {
                    string userDir = Path.Combine(ImageFolder, person.Id.ToString());
                    if (person.Avatar != null)
                        System.IO.File.Delete(Path.Combine(userDir, person.Avatar));
                    else if (!Directory.Exists(userDir))
                        Directory.CreateDirectory(userDir);
                    person.Avatar = $"{Path.GetRandomFileName()}.{Path.GetExtension(model.Avatar.FileName)}";
                    await model.Avatar.WriteToFile(Path.Combine(userDir, person.Avatar));
                }
                person.Login = model.Username;
                if (!string.IsNullOrEmpty(model.NewPassword))
                    person.PasswordHash = Argon2.Hash(model.NewPassword);
                person.Role = model.Role;
                await context.SaveChangesAsync();
                return Redirect("/Home/Index");
            }
            else
            {
                ModelState.AddModelError("", "Неверный ID");
                return (View(model));
            }
        }

        [Authorize(Roles = "Admin")]
        public IActionResult UserDetails(int id)
        {
            Person person = context.People.Find(id);
            return View(person.ToUserModel());
        }


        [Authorize(Roles = "Admin")]
        public IActionResult DeleteUser(int id)
        {
            Person person = context.People.Find(id);
            return View(person.ToUserModel());
        }


        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> DelUser(int id)
        {
            Person person = context.People.Find(id);
            var groups = await context.Groups.ToListAsync();
            var groupmessages = await context.GroupMessages.ToListAsync();
            var messages = await context.PersonalMessages.ToListAsync();
            foreach (Group group in groups)
            {
                if (group.MembersOfTheGroup.Contains(person))
                {
                    group.MembersOfTheGroup.Remove(person);
                }
            }
            foreach (GroupMessage groupMessage in groupmessages)
            {
                if (groupMessage.Sender == person)
                {
                    context.GroupMessages.Remove(groupMessage);
                }
            }
            foreach (PersonalMessage message in messages)
            {
                if ((message.Sender == person) || (message.Receiver == person))
                {
                    context.PersonalMessages.Remove(message);
                }
            }
            await context.SaveChangesAsync();
            if (person != null)
            {
                context.People.Remove(person);
                await context.SaveChangesAsync();
            }
            return Redirect("ListUsers");
        }

        [Authorize]
        public IActionResult UserPage()
        {
            UserModel usr = CurrentUser.ToUserModel();        
            return View(usr);
        }
        
        private string GetContentType(string filename)
        {
            string contentType;
            new FileExtensionContentTypeProvider().TryGetContentType(filename, out contentType);
            return contentType ?? "application/octet-stream";
        }

        [Authorize]
        public async Task<IActionResult> Avatar(string username)
        {
            Person person = context.People.FirstOrDefault(p => p.Login == username);

            string filePath;
            if (person == null || person.Avatar == null)
                filePath = Path.Combine(hostEnvironment.ContentRootPath, "DefaultImages", "no_ava.png");
            else
                filePath = Path.Combine(ImageFolder, person.Id.ToString(), person.Avatar);
            string contentType = GetContentType(filePath);
            byte[] imgBytes = await System.IO.File.ReadAllBytesAsync(filePath);
            return File(imgBytes, contentType);
        }
        
        [Authorize(Roles = "User")]
        public IActionResult ListDialogs()
        {
            UserModel usr = CurrentUser.ToUserModel();  
            IQueryable<Person> persons = from person in context.People
                where (person.Id != usr.Id) && (person.Role != UserRole.Admin)
                select person;
            return View(persons);
        }
        
        [Authorize(Roles = "User")]
        public IActionResult GetPersonalDialog(int id)
        {
            UserModel usr = CurrentUser.ToUserModel(); 
            Person sender = context.People.Find(usr.Id);
            Person receiver = context.People.Find(id);
            IQueryable<PersonalMessage> messages = from message in context.PersonalMessages
                orderby message.TimeOfDispatch descending 
                where ((message.Sender.Id == sender.Id) && (message.Receiver.Id == receiver.Id)) || 
                      ((message.Receiver.Id == sender.Id) && (message.Sender.Id == receiver.Id))
                select message;
            DialogModel model = new DialogModel()
            {
                Messages = messages,
                Receiver = id
            };
            return View(model);
        }
        
        [HttpPost]
        [Authorize(Roles = "User")]
        public async Task<IActionResult> SendPersonalMessage(DialogModel model)
        {
            UserModel usr = CurrentUser.ToUserModel();
            Person sender = context.People.Find(usr.Id);
            Person receiver = context.People.Find(model.Receiver);
            PersonalMessage message = new PersonalMessage()
            {
                MessageText = model.MessageText,
                Sender = sender,
                Receiver = receiver,
                TimeOfDispatch = DateTime.Now
            };
            await context.PersonalMessages.AddAsync(message);
            await context.SaveChangesAsync();
            return Redirect("/Account/GetPersonalDialog/" + model.Receiver);
        }
        
        [Authorize(Roles = "User")]
        public async Task<IActionResult> ListGroupDialogs()
        {
            UserModel usr = CurrentUser.ToUserModel();
            Person sender = context.People.Find(usr.Id);
            var groups = await context.Groups.ToListAsync();
            ListGroupModel model = new ListGroupModel()
            {
                Groups = groups,
                Sender = sender
            };
            return View(model);
        }
        
        [HttpPost]
        [Authorize (Roles = "User")]
        public async Task<IActionResult> CreateGroup(ListGroupModel model)
        {
            UserModel usr = CurrentUser.ToUserModel();
            Person member = context.People.Find(usr.Id);
            Group IfExistsGroup = context.Groups.FirstOrDefault(p => p.Title == model.Title);
            if (IfExistsGroup == default)
            {
                Group group = new Group()
                {
                    Title = model.Title,
                    MembersOfTheGroup = new List<Person>()
                };
                group.MembersOfTheGroup.Add(member);
                member.GroupsUser.Add(group);
                await context.Groups.AddAsync(group);
                await context.SaveChangesAsync();
            }
            return Redirect("/Account/ListGroupDialogs/");
        }
        
        [Authorize (Roles = "User")]
        public async Task<IActionResult> EnterToGroup(int id)
        {
            UserModel usr = CurrentUser.ToUserModel();
            Person member = await context.People.FindAsync(usr.Id);
            Group group = await context.Groups.FindAsync(id);
            group.MembersOfTheGroup.Add(member);
            await context.SaveChangesAsync();
            return Redirect("/Account/ListGroupDialogs/");
        }
        
        [Authorize(Roles = "User")]
        public async Task<IActionResult> GetGroupDialog(int id)
        {
            var messages = await context.GroupMessages.OrderByDescending(p => p.TimeOfDispatch).ToListAsync();
            List<GroupMessage> result = new List<GroupMessage>();
            foreach (GroupMessage groupMessage in messages)
            {
                if (groupMessage.RecipientGroup.Id == id)
                {
                    result.Add(groupMessage);
                }
            }
            GroupDialogModel model = new GroupDialogModel()
            {
                Messages = result,
                RecipientGroup = id
            };
            return View(model);
        }
        
        [HttpPost]
        [Authorize(Roles = "User")]
        public async Task<IActionResult> SendGroupMessage(GroupDialogModel model)
        {
            UserModel usr = CurrentUser.ToUserModel();
            Person sender = context.People.Find(usr.Id);
            Group group = context.Groups.Find(model.RecipientGroup);
            GroupMessage message = new GroupMessage()
            {
                MessageText = model.MessageText,
                Sender = sender,
                RecipientGroup = group,
                TimeOfDispatch = DateTime.Now
            };
            await context.GroupMessages.AddAsync(message);
            await context.SaveChangesAsync();
            return Redirect("/Account/GetGroupDialog/" + model.RecipientGroup);
        }
    }
}
