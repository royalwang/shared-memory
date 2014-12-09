<?
/** Easy caching in Shared memory
 * Writed by Zdenek Kops in 2013; zdenekkops@gmail.com
 * Thanks for inspiration to makr@makrit.net at http://www.php.net/manual/en/book.shmop.php
 * Requirements: PHP 5.3+ with --enable-shmop
 * Tested on: CentOS with PHP 5.4 (php54w php54w-process)
 *
 * Common using: shmem::save(STRING $name, MIXED $data [, STRING $password [, OCTAL $permissions]])
 *               shmem::read(STRING $name [, STRING $password])
 *               shmem::delete(STRING $name [, STRING $password])
 *               shmem::destroy([STRING $password]) // delete all caches saved with $password
 *               shmem::destroy() // delete all caches saved by this tool (regardless of any passwords)
 *
 * Feature: You can protect your caches with parameter password or initialize object with setting the password.
 * Password using: $shmem=new shmem(STRING $password) // now every use will be protected
 *                 $shmem->save(STRING $name, MIXED $data [, OCTAL $permissions])
 *                 $shmem->read(STRING $name)
 *                 $shmem->delete(STRING $name)
 *                 $shmem->destroy() // delete all caches saved with your $password (for delete regardless call it twice)
 *
 * Impotant notes:
 *   1. If you no longer need some cache, delete it. If no one, use shmem::destroy(). Else data will stay in memory forever.
 *   2. If you are using an another method for caching in shared memory, avoid to use key 1. Else this cache system will crash.
 *   3. If you want to use original keys (replacing my name-method), build new class extends shmem. Then do not care about key 1.
 *   4. Max size of all caches together is generally set to 68719476736. If you want more, carefully edit /proc/sys/kernel/shmmax
 *      By my experience, this tool is not usefull to save big data (every value is serialized).
 *
 */

class shmem{

  const SET_NEW_ID=1;
  const DISCARD_FOUND_ID=2;
  const ERR_PASSWD='No password.';
  const ERR_CALLABLE='Hash function is not callable.';

    // I think that faster execution and shorter returned string are more important than safety in this situation.
  const PROTECTION='crc32'; // You can define new hash function on your own, so there must be it's name or anonymous function.
  private $hashed_password=NULL;

  function __construct($password){
    if(empty($password)) throw new Exception(self::ERR_PASSWD);
    if(!is_callable(self::PROTECTION)) throw new Exception(self::ERR_CALLABLE);
    self::$hashed_password=call_user_func(self::PROTECTION, $password);
  }

  public static function save($name, $data, $password=NULL, $permissions=0666){
    if(isset($password) and is_string($password)){
      if(!is_callable(self::PROTECTION)) throw new Exception(self::ERR_CALLABLE);
      $password=call_user_func(self::PROTECTION, $password);
      return self::protected_save($name, $data, $password, $permissions);
    }
    if(isset(self::$hashed_password)) return self::protected_save($name, $data, self::$hashed_password, $permissions);
    return self::save_id(self::get_id($name, self::SET_NEW_ID), $data, $permissions);
  }

  public static function read($name, $password=NULL){
    if(isset($password)){
      if(!is_callable(self::PROTECTION)) throw new Exception(self::ERR_CALLABLE);
      $password=call_user_func(self::PROTECTION, $password);
      return self::protected_read($name, $password);
    }
    if(isset(self::$hashed_password)) return self::protected_read($name, self::$hashed_password);
    if($id=self::get_id($name)) return self::read_id($id);
    return false;
  }

  public static function delete($name, $password=NULL){
    if(isset($password)){
      if(!is_callable(self::PROTECTION)) throw new Exception(self::ERR_CALLABLE);
      $password=call_user_func(self::PROTECTION, $password);
      return self::protected_delete($name, $password);
    }
    if(isset(self::$hashed_password)) return self::protected_delete($name, self::$hashed_password);
    if($id=self::get_id($name, self::DISCARD_FOUND_ID)) return self::delete_id($id);
    return false;
  }

  public static function destroy($password=NULL){
    if(isset($password)) $password=call_user_func(self::PROTECTION, $password);
    elseif(isset(self::$hashed_password)) $password=self::$hashed_password;
    if(!empty($password)){
      if($password==self::$hashed_password) return self::__destruct();
      if($id=self::get_id($password) and $sessions=self::read_id($id) and count($sessions)>0){
        foreach($sessions as $id) self::delete_id($id);
        return true;
      }
    }
    else{
      if($sessions=self::read_id(1)) foreach($sessions as $id) self::delete_id($id);
      return self::delete_id(1);
    }
    return false;
  }

  protected static function protected_save($name, $data, $password, $permissions){
    $id=self::get_id($password, self::SET_NEW_ID);
    return self::save_id(self::get_id($name, self::SET_NEW_ID, $id), $data, $permissions);
  }

  protected static function protected_read($name, $password){
    if($id=self::get_id($password) and $id=self::get_id($name, 0, $id)) return self::read_id($id);
    return false;
  }

  protected static function protected_delete($name, $password){
    if($id=self::get_id($password) and $id=self::get_id($name, self::DISCARD_FOUND_ID, $id)) return self::delete_id($id);
    return false;
  }

  protected static function get_id($name, $options=0, $index=1){
    $sessions=self::read_id($index);
    if(isset($sessions[$name])){
      $id=$sessions[$name];
      if($options===self::DISCARD_FOUND_ID){
        unset($sessions[$name]);
        self::save_id($index, $sessions);
      }
      return $id;
    }
    elseif($options===self::SET_NEW_ID){
      for($new_id=count($sessions)+$index+1; self::read_id($new_id); ++$new_id); // now $new_id contains empty index
      $sessions[$name]=$new_id;
      self::save_id($index, $sessions);
      return $new_id;
    }
    return false;
  }

  protected static function save_id($id, $data, $permissions=0666){
    self::delete_id($id);
    $serialized=serialize($data);
    $shmid=shmop_open($id, 'c', $permissions, strlen($serialized));
    if($shmid){
      $return=shmop_write($shmid, $serialized, 0);
      shmop_close($shmid);
      return $return;
    }
    return false;
  }

  protected static function read_id($id){
    if($shmid=@shmop_open($id, 'a', 0, 0)){
      $data=shmop_read($shmid, 0, shmop_size($shmid));
      if($data){
        shmop_close($shmid);
        return unserialize($data);
      }
    }
    return false;
  }

  protected static function delete_id($id){
    if($shmid=@shmop_open($id, 'a', 0, 0) and shmop_delete($shmid)){
      shmop_close($shmid);
      return true;
    }
    return false;
  }

}