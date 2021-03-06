using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;
using JwtTest.EF;

namespace JwtTest.Models
{
    public class GroupDialogModel
    {
        public List<GroupMessage> Messages{ get; set; }
        
        public int RecipientGroup { get; set; }
        
        [DisplayName("Сообщение")]
        [Required(ErrorMessage = "Текст сообщения не может быть пустым")]
        public string MessageText { get; set;}
    }
}
