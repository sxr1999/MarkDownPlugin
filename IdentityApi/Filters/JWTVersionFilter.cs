using System.Security.Claims;
using IdentityApi.Attributes;
using IdentityApi.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Mvc.Filters;

namespace IdentityApi.Filters;

public class JWTVersionFilter : IAsyncActionFilter
{
    private readonly UserManager<MyUser> _userManager;

    public JWTVersionFilter(UserManager<MyUser> userManager)
    {
        _userManager = userManager;
    }

    public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
    {
        ControllerActionDescriptor controller = context.ActionDescriptor as ControllerActionDescriptor;

        if (controller==null)
        {
            await next();
            return;
        }

        if (controller.MethodInfo.GetCustomAttributes(typeof(NotCheckJWTVersionAttribute), true).Any())
        {
            await next();
            return;
        }


        var JWTVersion = context.HttpContext.User.FindFirstValue("JWTVersion");
        if (JWTVersion==null)
        {
            context.Result = new ObjectResult("Token中不包含jwt版本信息")
            {
                StatusCode = 400

            };
            return;
        }


        var userInfo =await _userManager.FindByIdAsync(context.HttpContext.User.FindFirstValue(ClaimTypes.NameIdentifier));

        if (userInfo==null)
        {
            context.Result = new ObjectResult("没有相对应的用户信息")
            {
                StatusCode = 400

            };
            return;
        }

        long jwt = Convert.ToInt64(JWTVersion);
        
        if (userInfo.JWTVersion > jwt)
        {
            context.Result = new ObjectResult("客户端jwt失效")
            {
                StatusCode = 400

            };
            return;
        }

        await next();
    }
}