#pragma checksum "C:\Users\igri-\Desktop\CSHARP\Kursach2\TestTemplate-master\JwtTest\Views\Account\UserDetails.cshtml" "{ff1816ec-aa5e-4d10-87f7-6f4963833460}" "6545655a295a288708d3640a315c636c740be70b"
// <auto-generated/>
#pragma warning disable 1591
[assembly: global::Microsoft.AspNetCore.Razor.Hosting.RazorCompiledItemAttribute(typeof(AspNetCore.Views_Account_UserDetails), @"mvc.1.0.view", @"/Views/Account/UserDetails.cshtml")]
namespace AspNetCore
{
    #line hidden
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.Rendering;
    using Microsoft.AspNetCore.Mvc.ViewFeatures;
#nullable restore
#line 1 "C:\Users\igri-\Desktop\CSHARP\Kursach2\TestTemplate-master\JwtTest\Views\_ViewImports.cshtml"
using JwtTest;

#line default
#line hidden
#nullable disable
#nullable restore
#line 2 "C:\Users\igri-\Desktop\CSHARP\Kursach2\TestTemplate-master\JwtTest\Views\_ViewImports.cshtml"
using JwtTest.Models;

#line default
#line hidden
#nullable disable
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"6545655a295a288708d3640a315c636c740be70b", @"/Views/Account/UserDetails.cshtml")]
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"43d935b47f8e065cd593aa0163542e8cf7725664", @"/Views/_ViewImports.cshtml")]
    public class Views_Account_UserDetails : global::Microsoft.AspNetCore.Mvc.Razor.RazorPage<JwtTest.Models.UserModel>
    {
        #pragma warning disable 1998
        public async override global::System.Threading.Tasks.Task ExecuteAsync()
        {
#nullable restore
#line 2 "C:\Users\igri-\Desktop\CSHARP\Kursach2\TestTemplate-master\JwtTest\Views\Account\UserDetails.cshtml"
  
    ViewData["Title"] = $"Информация о пользователе {Model.Username}";

#line default
#line hidden
#nullable disable
            WriteLiteral("<div>\r\n    <h4>UserModel</h4>\r\n    <hr />\r\n    <dl class=\"row\">\r\n        <dt class=\"col-sm-2\">\r\n            ");
#nullable restore
#line 10 "C:\Users\igri-\Desktop\CSHARP\Kursach2\TestTemplate-master\JwtTest\Views\Account\UserDetails.cshtml"
       Write(Html.DisplayNameFor(model => model.Username));

#line default
#line hidden
#nullable disable
            WriteLiteral("\r\n        </dt>\r\n        <dd class=\"col-sm-10\">\r\n            ");
#nullable restore
#line 13 "C:\Users\igri-\Desktop\CSHARP\Kursach2\TestTemplate-master\JwtTest\Views\Account\UserDetails.cshtml"
       Write(Html.DisplayFor(model => model.Username));

#line default
#line hidden
#nullable disable
            WriteLiteral("\r\n        </dd>\r\n        <dt class=\"col-sm-2\">\r\n            ");
#nullable restore
#line 16 "C:\Users\igri-\Desktop\CSHARP\Kursach2\TestTemplate-master\JwtTest\Views\Account\UserDetails.cshtml"
       Write(Html.DisplayNameFor(model => model.Role));

#line default
#line hidden
#nullable disable
            WriteLiteral("\r\n        </dt>\r\n        <dd class=\"col-sm-10\">\r\n            ");
#nullable restore
#line 19 "C:\Users\igri-\Desktop\CSHARP\Kursach2\TestTemplate-master\JwtTest\Views\Account\UserDetails.cshtml"
       Write(Html.DisplayFor(model => model.Role));

#line default
#line hidden
#nullable disable
            WriteLiteral("\r\n        </dd>\r\n        <dt class=\"col-sm-2\">\r\n            Аватар\r\n        </dt>\r\n        <dd class=\"col-sm-10\">\r\n            <img");
            BeginWriteAttribute("src", " src=\"", 697, "\"", 743, 2);
            WriteAttributeValue("", 703, "/Account/Avatar?username=", 703, 25, true);
#nullable restore
#line 25 "C:\Users\igri-\Desktop\CSHARP\Kursach2\TestTemplate-master\JwtTest\Views\Account\UserDetails.cshtml"
WriteAttributeValue("", 728, Model.Username, 728, 15, false);

#line default
#line hidden
#nullable disable
            EndWriteAttribute();
            WriteLiteral(" alt=\"Аватар\" height=\"200\" />\r\n        </dd>\r\n    </dl>\r\n</div>\r\n");
        }
        #pragma warning restore 1998
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.ViewFeatures.IModelExpressionProvider ModelExpressionProvider { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.IUrlHelper Url { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.IViewComponentHelper Component { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.Rendering.IJsonHelper Json { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.Rendering.IHtmlHelper<JwtTest.Models.UserModel> Html { get; private set; }
    }
}
#pragma warning restore 1591
