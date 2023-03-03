using JetBrains.Annotations;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace authorization_library;

[PublicAPI]
public class UserAuthenticationAttribute : ActionFilterAttribute
  {
    
    public override void OnActionExecuting(ActionExecutingContext actionContext)
    {
      var jwtBody = actionContext.HttpContext.GetUser();
      if (jwtBody != null)
        return;
      actionContext.Result = new UnauthorizedResult();
      base.OnActionExecuting(actionContext);
    }
  }



  