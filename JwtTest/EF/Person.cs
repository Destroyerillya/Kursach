using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;
using JwtTest.EF;

namespace JwtTest.EF
{
    public enum UserRole
    {
        Admin = 0,
        User = 1
    }

    public class Person
    {
        public int Id { get; set; }
        [DisplayName("Имя пользователя")]
        public string Login { get; set; }
        public string PasswordHash { get; set; }
        public UserRole Role { get; set; }
        [DisplayName("Аватар")]
        public string Avatar { get; set; }
        
        public virtual List<Group> GroupsUser { get; set;}
    }
}
