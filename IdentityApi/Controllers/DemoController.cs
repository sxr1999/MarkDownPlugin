using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using IdentityApi.Attributes;
using IdentityApi.Filters;
using IdentityApi.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace IdentityApi.Controllers
{
    [Route("api/[controller]/[action]")]
    [ApiController]
    public class DemoController : ControllerBase
    {
        private readonly UserManager<MyUser> _userManager;
        private readonly RoleManager<MyRole> _roleManager;
        private readonly IWebHostEnvironment _environment;
        private readonly IOptionsSnapshot<JWTSettings> jwtsettings;

        public DemoController(UserManager<MyUser> userManager,RoleManager<MyRole> roleManager,IWebHostEnvironment environment,IOptionsSnapshot<JWTSettings> jwtsettings)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _environment = environment;
            this.jwtsettings = jwtsettings;
        }


        [HttpGet]
        [Authorize]
        public string Test()
        {
            return "OK";
        }
        

        [HttpGet]
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        
        public string Success()
        {
            var Username = this.User.FindFirst(ClaimTypes.Name);
            return "Login Success: "+Username.Value;
        }


        [HttpPost]
        [NotCheckJWTVersion]
        public async Task<ActionResult<string>> Login(UserViewModel model)
        {
            var user = await _userManager.FindByNameAsync(model.UserName);
            if (user==null)
            {
                return BadRequest("用户不存在");
            }

            var result = await _userManager.CheckPasswordAsync(user, model.Password);
            if (!result)
            {
                return BadRequest("密码错误");
            }

            user.JWTVersion++;
            await _userManager.UpdateAsync(user);
            var claims = new List<Claim>();
            claims.Add(new Claim(ClaimTypes.NameIdentifier,user.Id.ToString()));
            claims.Add(new Claim("JWTVersion",user.JWTVersion.ToString()));
            claims.Add(new Claim(ClaimTypes.Name,user.UserName));
            var roles = await _userManager.GetRolesAsync(user);
            foreach (var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role,role));
            }


            string key = jwtsettings.Value.Key;
            DateTime expir = DateTime.Now.AddSeconds(jwtsettings.Value.ExpireSeconds);
            byte[] secBytes = Encoding.UTF8.GetBytes(key);
            var secKey = new SymmetricSecurityKey(secBytes);
            var credentials = new SigningCredentials(secKey, SecurityAlgorithms.HmacSha256Signature);
            var tokenDescriptor = new JwtSecurityToken(claims:claims,expires:expir,signingCredentials: credentials);
            string token = new JwtSecurityTokenHandler().WriteToken(tokenDescriptor);
            
            return Ok(token);

        }


        [HttpPost]
        public async Task<ActionResult<string>> Test1()
        {
            var role =await _roleManager.RoleExistsAsync("Admin");
            if (!role)
            {
                MyRole newRole = new MyRole()
                {
                    Name = "Admin"
                };
                var result = await _roleManager.CreateAsync(newRole);
                if (!result.Succeeded)
                {
                    return BadRequest("create role failed");
                }
            }

            var user1 = await  _userManager.FindByNameAsync("sxr");
            if (user1==null)
            {
                var result1 =await _userManager.CreateAsync(new MyUser(){UserName = "sxr"},"123456");
                if (!result1.Succeeded)
                {
                    return BadRequest("create User failed");
                }
            }

            var result2 = await  _userManager.IsInRoleAsync(user1,"Admin");
            if (!result2)
            {
                var result3 = await _userManager.AddToRoleAsync(user1,"Admin");
                if (!result3.Succeeded)
                {
                    return BadRequest("add user to role failed");
                }
            }

            return Ok();
        }

        [HttpPost]
        public async Task<ActionResult<string>> ResetPassWord(string userName)
        {
            var user = await _userManager.FindByNameAsync(userName);
            if (user==null)
            {
                return BadRequest("用户不存在");
            } 

            var token =await _userManager.GeneratePasswordResetTokenAsync(user);
            return Ok($"验证码是:{token}");
        }

        [HttpPut]
        public async Task<ActionResult<string>> ChangePassWord(string userName,string token,string newPassword)
        {
            var user = await _userManager.FindByNameAsync(userName);
            if (user==null)
            {
                return BadRequest("用户不存在");
            }

            var result =await _userManager.ResetPasswordAsync(user,token,newPassword);
            if (result.Succeeded)
            {
                await _userManager.ResetAccessFailedCountAsync(user);
                return Ok("密码重制成功");
            }
            else
            {
                await _userManager.AccessFailedAsync(user);
                return BadRequest("修改密码失败");
            }
        }




        [HttpPost]
        public async Task<ActionResult<string>> CheckUserInfo(UserViewModel req)
        {
            string userName = req.UserName;
            string passWord = req.Password;
            var user = await _userManager.FindByNameAsync(userName);
            if (user==null)
            {
                if (_environment.IsDevelopment())
                {
                    return BadRequest($"{userName} 用户名不存在");
                }

                return BadRequest();
            }

            if (await _userManager.IsLockedOutAsync(user))
            {
                return BadRequest($"{userName}已经被锁定,锁定结束时间:"+user.LockoutEnd);
            }

            var result = await _userManager.CheckPasswordAsync(user, passWord);
            if (!result)
            {
                await _userManager.AccessFailedAsync(user);
                
                return BadRequest("密码错误");
                
            }
            else
            {
                await _userManager.ResetAccessFailedCountAsync(user);
                return Ok("登录成功");
            }
        }
    }
}
