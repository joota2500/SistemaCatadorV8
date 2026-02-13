from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User, Municipality


# -------------------------------------
# MUNICÍPIOS
# -------------------------------------
@admin.register(Municipality)
class MunicipalityAdmin(admin.ModelAdmin):
    list_display = ("id", "name", "slug", "is_active")
    search_fields = ("name", "slug")
    list_filter = ("is_active",)


# -------------------------------------
# USUÁRIOS PERSONALIZADOS
# -------------------------------------
@admin.register(User)
class UserAdmin(BaseUserAdmin):
    fieldsets = BaseUserAdmin.fieldsets + (
        ("Informações adicionais", {
            "fields": (
                "role",
                "municipality",
                "permission_level",
                "full_name",
                "nickname",
                "cpf",
                "birth_date",
                "phone",
                "address",
                "photo",
            ),
        }),
    )

    list_display = (
        "username",
        "full_name",
        "role",
        "municipality",
        "permission_level",
        "is_active",
    )

    list_filter = ("role", "municipality", "permission_level", "is_active")

    search_fields = ("username", "full_name", "cpf")
