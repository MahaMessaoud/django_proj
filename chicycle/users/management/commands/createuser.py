from django.core.management.base import BaseCommand
from users.models import CustomUser

class Command(BaseCommand):
    help = 'Create a regular user'

    def handle(self, *args, **kwargs):
        if not CustomUser.objects.filter(username='user').exists():
            CustomUser.objects.create_user(
                username='user',
                email='user@example.com',
                password='password',
                role='user'
            )
            self.stdout.write(self.style.SUCCESS('Successfully created User'))
        else:
            self.stdout.write(self.style.WARNING('User already exists'))
