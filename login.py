import utils
import os

def test(body):
    print(body)
    res = {"body": {"success":"tst"}, "file": "None"}
    return res, None

def before_upload(body):
    print("Function_before_upload:", body)
    res={}
    res["file"] = "Upload"
    res["fileinfo"] = body
    res["fileinfo"]["filepath"] = "D:\Code\TestFile\Server\TestFile.zip"
    # res["fileinfo"]["checksum"] = "123" #假设校验失败
    # 需要返回res和回调函数
    return res, after_upload

def after_upload(status, body):
    # 成功还是失败，前端的消息（body）
    print("Function_after_upload:", status)
    if status == "success":
        res = {"status": "success"}
    else:
        res = {"status": "fail"}
    return res

def before_download(body):
    print("Function_before_download:", body)
    res={}
    res["file"] = "Download"
    # res["fileinfo"] = body
    filepath = "D:\Code\TestFile\Server\TestFile.zip"
    res["fileinfo"] = {}
    res["fileinfo"]["filepath"] = filepath
    res["fileinfo"]["filesize"] = os.path.getsize(filepath)
    res["fileinfo"]["checksum"] = utils.sha1_file(filepath) #假设校验失败
    # 需要返回res和回调函数
    return res, after_download

def after_download(status, body):
    # 成功还是失败，前端的消息（body）
    print("Function_after_download:", status)
    if status == "success":
        res = {"status": "success"}
    else:
        res = {"status": "fail"}
    return res