from rest_framework.response import Response 

class Responses: 
    @staticmethod
    def response_api(message , status  , data = None , error = None  ):
        reponse_data = {
            'message' : message , 
            'status' : status, 
        }
        if error :
            reponse_data['error'] = error 
        if data :
            reponse_data['data'] = data
         
        return Response(reponse_data)
    