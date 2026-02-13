from .models import User


def programador_count(request):
    if not request.user.is_authenticated:
        return {}
    try:
        count = User.objects.filter(role="programador").count()
    except:
        count = 0
    return {"prog_count": count}
