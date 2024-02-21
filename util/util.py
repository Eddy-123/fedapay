from abc import ABCMeta


class Util(metaclass=ABCMeta):
    __is_mbstring_available = None
    __is_hash_equals_available = None
    
    @classmethod
    def secure_compare(cls, a, b):
        if cls.__is_hash_equals_available == None:
            # todo: what is hash_equals 
            cls.__is_hash_equals_available = 'hash_equals' in globals()
            
        if cls.__is_hash_equals_available:
            # todo: return result of hash_equals()
            pass
        else:
            if len(a) != len(b):
                return False
            
            result = 0
            for i in range(len(a)):
                result |= ord(a[i]) ^ ord(b[i])
            
            print('RESULT = ', result)
            return result == 0
        
    