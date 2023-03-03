using ATI.Services.Common.Behaviors;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Mvc.Filters;

namespace authorization_library;

[PublicAPI]
public sealed class ValidateModelStateAttribute : ActionFilterAttribute
{
    public override void OnActionExecuting(ActionExecutingContext actionContext)
    {
        if (actionContext.ModelState.IsValid)
            return;
        actionContext.Result = CommonBehavior.GetActionResult(ActionStatus.BadRequest, actionContext.ModelState);
        base.OnActionExecuting(actionContext);
    }
}