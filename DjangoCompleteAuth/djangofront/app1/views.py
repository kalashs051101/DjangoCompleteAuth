# from django.shortcuts import render
from app1.serializers import *
from rest_framework.views import APIView
from rest_framework.response import Response
from django.contrib.auth import authenticate
from app1.renderers import *
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import status
from rest_framework.permissions import IsAuthenticated

def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }
# Create your views here.
class UserRegistrationView(APIView):
    renderer_classes = [userRenderer]
    def get(self,request, format=None):
        data=User.objects.all()
        serializer=UserRegistrationSerializer(data,many=True)
        
        return Response({'msg':"msg fetch bro",'data':serializer.data})
        # pass
    def post(self,request, format=None):
        
        # data = request.data
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user  = serializer.save()
            token = get_tokens_for_user(user)
            return Response({'token':token,'msg': "Registration succesful"},status=status.HTTP_201_CREATED)
        # else:
        #     return Response({})            
        return Response(serializer.errors,status=400)


class UserLoginView(APIView):
    renderer_classes = [userRenderer]
    def post(self,request):
        serializer= UserLoginSerializer(data=request.data)
        if serializer.is_valid():
            email=serializer.data['email']
            password=serializer.data['password']
            user = authenticate(email=email,password=password)
            if user is not None:
                token = get_tokens_for_user(user)

                return Response({'token':token,'msg':'login success'},status=status.HTTP_200_OK)

            else:
                return Response({'errors':{'non-fields_errors':['email or password is not correct']}},status=status.HTTP_404_NOT_FOUND)
        # return Response({'msg':'login successful'})
        return Response(serializer.errors)

class UserProfileView(APIView):
    renderer_classes= [userRenderer]
    permission_classes = [IsAuthenticated]
    def get(self,request,format=None):
        serializer=UserProfileSerializer(request.user)
        # if serializer.is_valid():
        return Response(serializer.data,status=status.HTTP_200_OK)

class UserChangePasswordView(APIView):
    renderer_classes=[userRenderer]
    permission_classes= [IsAuthenticated]
    def post(self,request,format=None):
        serializer=UserChangePasswordSerializer(data=request.data,context={'user':request.user})
        if serializer.is_valid(raise_exception=True):
            return Response({'msg':'password change successfully'})
        return Response({serializer.errors},status=status.HTTP_400_BAD_REQUEST)
        

class SendPasswordResetEmailView(APIView):
    renderer_classes= [userRenderer]
    def post(self,request,format=None):
        serializer=SendPasswordChangeEmailSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            return Response({'msg':'password reset link on your email..chech email'},status=status.HTTP_200_OK)
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)
        # pass

#RESET PASSWORD
class UserPasswordResetView(APIView):
    renderer_classes = [userRenderer]
    def post(self,request,uid,token,format=None):
        serializer = UserPasswordResetSerializer(data=request.data,context={'uid':uid,'token':token})
        if serializer.is_valid():
            return Response({'msg':'password reset successfully'},status=status.HTTP_200_OK)
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)



        # pass