from django.urls import path 
from backend_app.views import * 
from rest_framework.routers import DefaultRouter

router = DefaultRouter()
router.register(r'verify' , VerifyView , basename='verify')
router.register(r'change' , UpdatePassword , basename='change')
router.register(r'authenticate', AuthenticateManager , basename = 'authenticate')


urlpatterns = [
    
    path('updateProfile' , updateProfile.as_view() , name='updateProfile') , 
    path('testpin', TestPin.as_view() , name='testpin'),
    path('transaction', TransactionView.as_view() , name='transaction')  ,
    path('pending', PendingView.as_view() , name='pending') , 
    path('history', HistoryView.as_view() , name = 'history') ,
    path('execute', ExecuteView.as_view() , name = 'execute'),
    path('block', AllBlockView.as_view() , name = 'block') ,
    path('block/<block_id>/', BlockDetailView.as_view(), name='block_detail'),
]

urlpatterns += router.urls