from rest_framework import serializers, validators
from django.contrib.auth.models import User
from backend_app.models import *

import re

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta : 
        model = UserProfile
        fields = ('last_name', 'first_name', 'phoneNumber')
    

 
class UserInfoSerializer(serializers.ModelSerializer):
    profile = UserProfileSerializer() 
    class Meta:
        model = User
        fields = ('username', 'password' , 'email',  'profile')
        extra_kwargs = {
            'password': {'write_only': True},
        }
    def validate_password(self, value):
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', value):
            raise serializers.ValidationError("Passwords must have at least one special character")
        if not any(char.isdigit() for char in value):
            raise serializers.ValidationError("Passwords must have at least one number")
        if not any(char.isupper() for char in value):
            raise serializers.ValidationError("Passwords must have at least one upper character")
        if any(char.isspace() for char in value):
            raise serializers.ValidationError("Passwords cannot have spaces" )
        if not value:
            raise serializers.ValidationError("Passwords cannot be empty") 
        return value

    def validate_email(self, value):
        if not (re.search(r'[^@]*@[^@]*$' , value) ):
            raise serializers.ValidationError("Invalid email format. Please include the @ symbol.")
        if value == "": 
            raise serializers.ValidationError("Email cannot empty")
        return value
    

    def validate_username(self, value) :
        if not value : 
            raise serializers.ValidationError("Username cannot be empty")
        return value
    
    def create(self, validated_data):
        username = validated_data.get('username')
        password = validated_data.get('password')
        email = validated_data.get('email')
        profile_data = validated_data.get('profile')
        user = User.objects.create_user(
            username=username,
            password=password,
            email= email
        )
        UserProfile.objects.create(user = user , **profile_data)
        return user
    def update(self, instance, validated_data):
        try:
            profile_data = validated_data.get('profile')
            instance.email = validated_data.get('email', instance.email)
            password = validated_data.get('password')
            
            if password:
                instance.set_password(password)
            
            if profile_data:
                profile = instance.profile
                profile.last_name = profile_data.get('last_name', profile.last_name)
                profile.first_name = profile_data.get('first_name', profile.first_name)
                profile.phoneNumber = profile_data.get('phoneNumber', profile.phoneNumber)
                profile.save()

            instance.save()
            return instance

        except Exception as e:
            print(str(e))

        


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=150)
    password = serializers.CharField(write_only=True)

class SearchUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id','username', 'email', 'first_name', 'last_name','phoneNumber')

class HistoryModelSerializer(serializers.ModelSerializer):
    class Meta:
        model = HistoryModel
        fields = '__all__'


class SaveEmailSerializer(serializers.ModelSerializer):
    class Meta:
        model = SaveEmailModel 
        # gap loi neu nhu du lieu duoc truyen ve serializer khong day du 
        fields = ('username' , 'email', 'code' , 'expiration_time' )

