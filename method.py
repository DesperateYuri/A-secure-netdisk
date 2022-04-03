import login

methods = {
    "test": login.test,
    "upload": login.before_upload,
    "download": login.before_download
}


def method_handle(method, body):
    try:
        res, callback = methods[method](body)
        return res, callback
    except Exception as e:
        raise e
