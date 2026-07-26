from pyzbar.pyzbar import decode
import cv2
import numpy as np



def extract_url_from_qr(image_byte):
    raw_bytes=image_byte.read()
    array=np.frombuffer(raw_bytes,np.uint8)
    img=cv2.imdecode(array,cv2.IMREAD_COLOR)

    data,box,straight_qr=cv2.QRCodeDetector().detectAndDecode(img)
    if data:
        return data

    #pyzbar
    decoded=decode(img)
    if decoded:
        first_result=decoded[0].data.decode("utf-8")
        return first_result
    
    print("error:qr not found")
    return None
    


