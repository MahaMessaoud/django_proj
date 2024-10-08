from django.core.management.base import BaseCommand
from users.models import CustomUser

class Command(BaseCommand):
    help = 'Create a Super Admin'

    def handle(self, *args, **kwargs):
        if not CustomUser.objects.filter(username='superadmin').exists():
            CustomUser.objects.create_superuser(
                username='superadmin',
                email='superadmin@example.com',
                password='password',
                role='superadmin'
            )
            self.stdout.write(self.style.SUCCESS('Successfully created Super Admin'))
        else:
            self.stdout.write(self.style.WARNING('Super Admin already exists'))
