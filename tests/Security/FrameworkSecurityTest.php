<?php

use Illuminate\Cookie\Guard;
use Illuminate\Encryption\Encrypter;
use Illuminate\Encryption\DecryptException;
use Illuminate\Foundation\Application;
use Illuminate\View\Factory;
use Illuminate\View\Compilers\BladeCompiler;
use Illuminate\View\Engines\EngineResolver;
use Illuminate\View\FileViewFinder;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Events\Dispatcher;
use Illuminate\Validation\Validator;
use Symfony\Component\Translation\Translator;
use Symfony\Component\Translation\Loader\ArrayLoader;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\HttpKernelInterface;

class FrameworkSecurityTest extends PHPUnit_Framework_TestCase {

	public function testStringEncryptionDoesNotUnserializeObjects()
	{
		$encrypter = $this->encrypter();
		$payload = serialize(new FrameworkSecurityWakeup);
		FrameworkSecurityWakeup::$calls = 0;

		$this->assertSame($payload, $encrypter->decryptString($encrypter->encryptString($payload)));
		$this->assertSame(0, FrameworkSecurityWakeup::$calls);
		$this->assertSame(array('foo' => 'bar'), $encrypter->decrypt($encrypter->encrypt(array('foo' => 'bar'))));
	}

	public function testExistingSerializedCiphertextStillDecrypts()
	{
		// Produced by the original 4.2 encrypter with the test key of 32 "a" characters.
		$payload = trim(file_get_contents(__DIR__.'/fixtures/legacy-encrypted.txt'));
		$this->assertSame(array('legacy' => 'value'), $this->encrypter()->decrypt($payload));
	}

	public function testCookieRoundTripPreservesValuesAndOptions()
	{
		$kernel = new FrameworkSecurityKernel;
		$kernel->response->headers->setCookie(new Cookie('color', 'blue', time() + 600, '/path', 'example.com', true, true));
		$guard = new Guard($kernel, $this->encrypter());
		$response = $guard->handle(Request::create('/'));
		$cookie = $response->headers->getCookies()[0];

		$this->assertNotSame('blue', $cookie->getValue());
		$this->assertSame('/path', $cookie->getPath());
		$this->assertSame('example.com', $cookie->getDomain());
		$this->assertTrue($cookie->isSecure());
		$this->assertTrue($cookie->isHttpOnly());
		$this->assertSame('blue', $this->decryptCookies(array('color' => $cookie->getValue()))['color']);
	}

	public function testCookiesCannotBeMovedToAnotherNameOrArrayIndex()
	{
		$value = $this->encryptedCookie('color', 'blue');
		$this->assertNull($this->decryptCookies(array('other' => $value))['other']);
		$this->assertNull($this->decryptCookies(array('color' => array('x' => $value)))['color']);

		$value = $this->encryptedCookie('colors[x]', 'blue');
		$this->assertSame(array('x' => 'blue'), $this->decryptCookies(array('colors' => array('x' => $value)))['colors']);
		$this->assertNull($this->decryptCookies(array('colors' => array('y' => $value)))['colors']);
	}

	public function testCookieArraysRejectMalformedValues()
	{
		$this->assertNull($this->decryptCookies(array('color' => array('x' => null)))['color']);
		$this->assertNull($this->decryptCookies(array('color' => 42))['color']);
	}

	public function testLegacyAndOraclePayloadsAreRejectedWithoutObjectInstantiation()
	{
		$encrypter = $this->encrypter();
		$object = new FrameworkSecurityWakeup;
		$payloads = array(
			$encrypter->encrypt('blue'),
			$encrypter->encrypt($object),
			$encrypter->encrypt(serialize(array('object' => $object))),
			$encrypter->encryptString(serialize($object)),
		);
		FrameworkSecurityWakeup::$calls = 0;

		foreach ($payloads as $payload)
		{
			$this->assertNull($this->decryptCookies(array('session' => $payload))['session']);
		}

		$this->assertSame(0, FrameworkSecurityWakeup::$calls);
	}

	public function testSerializedObjectCookieNeverRunsWakeup()
	{
		$payload = $this->encrypter()->encrypt(new FrameworkSecurityWakeup);
		FrameworkSecurityWakeup::$calls = 0;
		$cookies = $this->decryptCookies(array('session' => $payload));

		$this->assertSame(0, FrameworkSecurityWakeup::$calls);
		$this->assertNull($cookies['session']);
	}

	public function testCookieSessionRejectsAnEncryptionOraclePayload()
	{
		$id = str_repeat('a', 40);
		$payload = $this->encrypter()->encrypt(serialize(array('object' => new FrameworkSecurityWakeup)));
		FrameworkSecurityWakeup::$calls = 0;
		$cookies = $this->decryptCookies(array($id => $payload));
		$handler = new Illuminate\Session\CookieSessionHandler(new Illuminate\Cookie\CookieJar, 60);
		$handler->setRequest(Request::create('/', 'GET', array(), $cookies));
		$session = new Illuminate\Session\Store('session', $handler, $id);
		$session->start();

		$this->assertNull($session->get('object'));
		$this->assertSame(0, FrameworkSecurityWakeup::$calls);
	}

	public function testCookieSessionReadsAProperlyBoundSessionPayload()
	{
		$id = str_repeat('a', 40);
		$payload = $this->encryptedCookie($id, serialize(array('foo' => 'bar')));
		$cookies = $this->decryptCookies(array($id => $payload));
		$handler = new Illuminate\Session\CookieSessionHandler(new Illuminate\Cookie\CookieJar, 60);
		$handler->setRequest(Request::create('/', 'GET', array(), $cookies));
		$session = new Illuminate\Session\Store('session', $handler, $id);
		$session->start();

		$this->assertSame('bar', $session->get('foo'));
	}

	public function testMalformedEncryptionPayloadsFailBeforeDecryption()
	{
		$encrypter = $this->encrypter();
		$valid = json_decode(base64_decode($encrypter->encryptString('blue')), true);
		$payloads = array(null, array(), 42, base64_encode('true'), base64_encode('[]'));

		foreach (array('iv', 'value', 'mac') as $key)
		{
			foreach (array(null, array(), 0, '') as $value)
			{
				$invalid = $valid;
				$invalid[$key] = $value;
				$payloads[] = base64_encode(json_encode($invalid));
			}
		}

		foreach (array('iv' => base64_encode('short'), 'value' => '!!!', 'mac' => str_repeat('0', 64)) as $key => $value)
		{
			$invalid = $valid;
			$invalid[$key] = $value;
			$payloads[] = base64_encode(json_encode($invalid));
		}

		foreach ($payloads as $payload)
		{
			try
			{
				$encrypter->decryptString($payload);
				$this->fail('Malformed encryption payload was accepted.');
			}
			catch (DecryptException $e)
			{
				$this->assertInstanceOf('Illuminate\Encryption\DecryptException', $e);
			}
		}
	}

	public function testWebEnvironmentIgnoresQueryStringArgvWhileConsoleHonorsIt()
	{
		$hadArgs = array_key_exists('argv', $_SERVER);
		$args = $hadArgs ? $_SERVER['argv'] : null;
		$_SERVER['argv'] = array('--env=local');

		try
		{
			$app = new FrameworkSecurityApplication;
			$this->assertSame('production', $app->detectEnvironment(function() { return 'production'; }));
			$app->console = true;
			$this->assertSame('local', $app->detectEnvironment(function() { return 'production'; }));
		}
		catch (Exception $e)
		{
			if ($hadArgs) $_SERVER['argv'] = $args;
			else unset($_SERVER['argv']);
			throw $e;
		}

		if ($hadArgs) $_SERVER['argv'] = $args;
		else unset($_SERVER['argv']);
	}

	public function testBladeParentIsResolvedAtRenderTime()
	{
		$factory = $this->viewFactory();
		$compiler = new BladeCompiler(new Filesystem, null);
		$compiled = $compiler->compileString("@section('content')child @parent\n@endsection");
		$this->assertContains('getParentPlaceholder()', $compiled);
		$this->render($compiled, $factory);
		$factory->startSection('content', 'parent');
		$this->assertSame('child parent', $factory->yieldContent('content'));
		$this->assertSame($factory->getParentPlaceholder(), $factory->getParentPlaceholder());
		$this->assertNotSame($factory->getParentPlaceholder(), $this->viewFactory()->getParentPlaceholder());
	}

	public function testEscapedUserInputCannotActAsABladeParentDirective()
	{
		$factory = $this->viewFactory();
		$compiler = new BladeCompiler(new Filesystem, null);
		$value = '@parent';
		$compiled = $compiler->compileString('@section(\'content\')<input value="{{{ $value }}}">@endsection');
		$this->render($compiled, $factory, $value);
		$factory->startSection('content', '" onclick="alert(1)');

		$this->assertSame('<input value="@parent">', $factory->yieldContent('content'));
		$this->assertSame('@parent', $factory->yieldContent('missing', '@parent'));
	}

	public function testUnusedBladeParentPlaceholdersAreRemoved()
	{
		$factory = $this->viewFactory();
		$compiler = new BladeCompiler(new Filesystem, null);
		$this->render($compiler->compileString("@section('content')child @parent\n@endsection"), $factory);
		$this->assertSame('child ', $factory->yieldContent('content'));
	}

	public function testEmailRuleRejectsHeaderInjection()
	{
		$translator = new Translator('en', new Symfony\Component\Translation\MessageSelector);
		$translator->addLoader('array', new ArrayLoader);

		foreach (array("user@example.com\r\nBcc: other@example.com", "\"user\r\nname\"@example.com", "user@example.com\n", "user@example.com\r", array('user@example.com')) as $email)
		{
			$validator = new Validator($translator, array('email' => $email), array('email' => 'email'));
			$this->assertFalse($validator->passes());
		}

		$validator = new Validator($translator, array('email' => 'user+tag@example.com'), array('email' => 'email'));
		$this->assertTrue($validator->passes());
	}

	public function testArrayFileRulesValidateLiteralAsteriskPlaceholderNames()
	{
		$translator = new Translator('en', new Symfony\Component\Translation\MessageSelector);
		$translator->addLoader('array', new ArrayLoader);
		$file = new Symfony\Component\HttpFoundation\File\UploadedFile(__FILE__, 'payload.php', null, null, null, true);
		$validator = new Validator($translator, array('files' => array('__asterisk__' => $file)), array('files' => 'array'));
		$validator->each('files', array('mimes:png'));

		$this->assertFalse($validator->passes());
		$this->assertArrayHasKey('files.__asterisk__', $validator->failed());
	}

	protected function encrypter()
	{
		return new Encrypter(str_repeat('a', 32));
	}

	protected function encryptedCookie($name, $value)
	{
		$kernel = new FrameworkSecurityKernel;
		$kernel->response->headers->setCookie(new Cookie($name, $value));
		$response = (new Guard($kernel, $this->encrypter()))->handle(Request::create('/'));
		return $response->headers->getCookies()[0]->getValue();
	}

	protected function decryptCookies(array $cookies)
	{
		$kernel = new FrameworkSecurityKernel;
		(new Guard($kernel, $this->encrypter()))->handle(Request::create('/', 'GET', array(), $cookies));
		return $kernel->cookies;
	}

	protected function viewFactory()
	{
		return new Factory(new EngineResolver, new FileViewFinder(new Filesystem, array()), new Dispatcher);
	}

	protected function render($compiled, $__env, $value = null)
	{
		eval('?>'.$compiled);
	}
}

class FrameworkSecurityKernel implements HttpKernelInterface {
	public $response;
	public $cookies;

	public function __construct()
	{
		$this->response = new Response;
	}

	public function handle(Request $request, $type = HttpKernelInterface::MASTER_REQUEST, $catch = true)
	{
		$this->cookies = $request->cookies->all();
		return $this->response;
	}
}

class FrameworkSecurityApplication extends Application {
	public $console = false;

	public function runningInConsole()
	{
		return $this->console;
	}
}

class FrameworkSecurityWakeup {
	public static $calls = 0;

	public function __wakeup()
	{
		static::$calls++;
	}
}
