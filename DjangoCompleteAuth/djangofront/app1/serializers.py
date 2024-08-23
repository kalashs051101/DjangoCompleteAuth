from rest_framework import serializers
from app1.models import *
from django.utils.encoding import force_bytes,smart_str,DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode,urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from app1.utils import *

class UserRegistrationSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(style={'input_type':'password'},write_only=True)
    class Meta:
        model=User
        fields=['email', 'name', 'password', 'password2', 'tc']
        extra_kwargs={
            'password': {'write_only': True}
        }
    def validate(self,attrs):
        password=attrs.get('password')
        password2=attrs.get('password2')

        if password!=password2:
            raise serializers.ValidationError('password does not match')
        return attrs
    
    def create(self, validated_data):
        # validated_data.pop('password2') 
        return User.objects.create_user(**validated_data)


class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)
    class Meta:
        model = User
        fields= ['email','password']

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model= User
        fields=['id','email','name']

class UserChangePasswordSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=255,style={'input_type':'password'},write_only=True)
    password2 = serializers.CharField(max_length=255,style={'input_type':'password'},write_only=True)
    class Meta:
        fields=['password','password2']

    def validate(self, attrs):
        password=attrs.get('password')
        password2=attrs.get('password2')
        user = self.context.get('user')
        if password !=password2:
            raise serializers.ValidationError('password not match')
        user.set_password(password)        #This hashes the password
        user.save()
        return attrs


class SendPasswordChangeEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)
    class Meta:
        fields=['email']

    def validate(self, attrs):
        email = attrs.get('email')
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uid=urlsafe_base64_encode(force_bytes(user.id))
            print("UID : ------",uid)
            token=PasswordResetTokenGenerator().make_token(user)
            print("token : -----",token)
            link = 'http://localhost:3000/app1/reset/'+ uid+'/'+token
            print('password reset link : ',link)

            #SEND EMAIL
            body = 'click folowing link to reset your password '+link
            data={
                'subject': 'reset your password',
                'body':body,
                'to_email':user.email
            }
            Util.send_email(data)

            return attrs
        else:
            raise serializers.ValidationError('you are not a registered user ')

class UserPasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=255,style={'input_type':'password'},write_only=True)
    password2 = serializers.CharField(max_length=255,style={'input_type':'password'},write_only=True)
    class Meta:
        fields=['password','password2']

    def validate(self, attrs):
        # try:
        password=attrs.get('password')
        password2=attrs.get('password2')
        # user = self.context.get('user')
        uid=self.context.get('uid')
        token=self.context.get('token')


        if password !=password2:
            raise serializers.ValidationError('password not match')
        id = smart_str(urlsafe_base64_decode(uid))
        user = User.objects.get(id=id)
        if not PasswordResetTokenGenerator().check_token(user,token):
            raise serializers.ValidationError('token is invalid or expired')
        
        user.set_password(password)        #This hashes the password
        user.save()
        return attrs
        # except:
        #     PasswordResetTokenGenerator().check_token(user,token)
        #     raise serializers.ValidationError('toen is invalid or expire')


